// Sign in with Google + собственная сессия — auth-сервис проекта. Разбиение
// на модули:
//
//   google.*  — Sign in with Google (аутентификация: разово подтвердить
//               личность, выпустить свою сессию).
//   auth.*    — своя сессия (JWT) + auth::authenticate(), которым остальные
//               модули (admin.*, и другие сервисы через JWKS) проверяют
//               авторизацию запроса.
//   pages.*   — HTML для браузерной части флоу.
//   devices.* — self-service "мои устройства": список активных сессий,
//               отзыв одной или всех кроме текущей (см. auth::authenticate).
//               Отличие от admin.* — управляет только СВОИМИ сессиями.
//   telegram.* — связывание Telegram-бота (wallet-telegram) с
//               пользователем: одноразовый код и его обмен на device-сессию.
//
// Кошельки (создание/удаление) сюда больше не входят — CRUD, что раньше
// временно жил тут же (wallet.*), выделен в отдельный сервис со своей БД,
// см. ../wallet-api.
//
// CPPHTTPLIB_OPENSSL_SUPPORT задаётся в CMakeLists.txt (глобальный compile
// definition), а не здесь через #define — так он действует одинаково во всех
// .cpp, независимо от порядка включения заголовков.

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <fstream>
#include <memory>
#include <sstream>
#include <string>
#include <unordered_set>

#include "admin.hpp"
#include "app_state.hpp"
#include "auth.hpp"
#include "db.hpp"
#include "devices.hpp"
#include "docs.hpp"
#include "google.hpp"
#include "httplib.h"
#include "redis_client.hpp"
#include "telegram.hpp"
#include "util/crypto.hpp"
#include "util/dotenv.hpp"
#include "util/log.hpp"
#include "util/metrics.hpp"
#include "version.hpp"

#ifdef _WIN32
#include <windows.h>
#endif

namespace {

// Классическая консоль Windows по умолчанию открывается не в UTF-8 (обычно
// OEM-кодовая страница вроде 866) — все наши кириллические строки (код
// собран с /utf-8, см. CMakeLists.txt) превращались бы в кашу при выводе
// через std::cout/cerr. Переключаем именно кодовую страницу КОНСОЛИ — это
// работает независимо от того, как программу запустили (двойной клик, из
// cmd, как служба через NSSM). Сами .bat-скрипты (scripts/windows/)
// намеренно оставлены на чистом ASCII без `chcp`: связка "chcp 65001 +
// нелатинские байты в исходнике .bat" — известный баг парсера cmd.exe,
// который начинает резать строки посреди многобайтовых UTF-8-последовательностей.
#ifdef _WIN32
void fix_console_encoding() {
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
}
#else
void fix_console_encoding() {}
#endif

std::string env_or(const char* key, const std::string& fallback) {
    const char* v = std::getenv(key);
    return (v != nullptr && *v != '\0') ? std::string(v) : fallback;
}

// "a@x.com, B@Y.com" -> {"a@x.com", "b@y.com"} — регистр email не должен
// иметь значения, и опечатки с пробелами вокруг запятой не должны молча
// исключать пользователя из списка (используется и для ADMIN_EMAILS, и для
// SUPPORT_EMAILS).
std::unordered_set<std::string> parse_email_list(const std::string& csv) {
    std::unordered_set<std::string> out;
    std::stringstream ss(csv);
    std::string item;
    while (std::getline(ss, item, ',')) {
        auto not_space = [](unsigned char c) { return std::isspace(c) == 0; };
        item.erase(item.begin(), std::find_if(item.begin(), item.end(), not_space));
        item.erase(std::find_if(item.rbegin(), item.rend(), not_space).base(), item.end());
        std::transform(item.begin(), item.end(), item.begin(),
                        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        if (!item.empty()) out.insert(item);
    }
    return out;
}

// "a, b" -> {"a", "b"} — та же обрезка пробелов, что и в parse_email_list
// выше, но без lowercase: используется для ALLOWED_REDIRECT_URIS, а это
// полноценные URL, регистр пути в общем случае значим (сам путь у нас везде
// "/auth/google/callback", уже нижним регистром, но раз это не email —
// решили не приводить произвольно).
std::unordered_set<std::string> parse_csv_list(const std::string& csv) {
    std::unordered_set<std::string> out;
    std::stringstream ss(csv);
    std::string item;
    while (std::getline(ss, item, ',')) {
        auto not_space = [](unsigned char c) { return std::isspace(c) == 0; };
        item.erase(item.begin(), std::find_if(item.begin(), item.end(), not_space));
        item.erase(std::find_if(item.rbegin(), item.rend(), not_space).base(), item.end());
        if (!item.empty()) out.insert(item);
    }
    return out;
}

std::string env_required(const char* key, const std::string& hint) {
    const char* v = std::getenv(key);
    if (v == nullptr || *v == '\0') {
        applog::error(std::string(key) + " must be set — " + hint + " (см. README.md)");
        std::exit(1);
    }
    return std::string(v);
}

bool env_bool(const char* key, bool fallback) {
    const char* v = std::getenv(key);
    if (v == nullptr) return fallback;
    std::string s(v);
    return s == "1" || s == "true" || s == "TRUE" || s == "True";
}

// Не льём в лог мегабайтные тела целиком — обрезаем и явно отмечаем факт
// обрезки в самой строке, а не молча теряем хвост незамеченным.
//
// Лимит — в СЫРЫХ байтах тела, не в байтах итоговой строки лога: на
// бинарных телах непечатные байты при JSON-экранировании раздуваются до
// 6 символов каждый — при старом лимите 4096 байт это ломало journald
// (резал строку на куски, `CONTAINER_PARTIAL_MESSAGE:true`) и fluent-bit
// (строгий JSON-парсер app_json падал на оборванном куске, запись
// оставалась без level/service/trace_id/msg — только сырой "message"),
// см. подробный разбор в wallet-api/src/main.cpp.
constexpr std::size_t kMaxLoggedBodyBytes = 1024;

std::string truncate_body(const std::string& body) {
    if (body.size() <= kMaxLoggedBodyBytes) return body;
    return body.substr(0, kMaxLoggedBodyBytes) + "...(обрезано, всего " +
           std::to_string(body.size()) + " байт)";
}

// Тело ответа для debug-лога. httplib сжимает res.body ДО вызова логгера
// (при CPPHTTPLIB_ZLIB_SUPPORT и Accept-Encoding клиента) — в лог шли байты
// gzip, нечитаемые. Сжатое тело не пишем, только кодировку и размер. Сам
// google-auth сейчас без zlib, но функция та же, что в остальных сервисах.
std::string loggable_response_body(const httplib::Response& res) {
    std::string encoding = res.get_header_value("Content-Encoding");
    if (!encoding.empty()) return "(сжато " + encoding + ", " + std::to_string(res.body.size()) + " байт)";
    return truncate_body(res.body);
}

uint64_t env_u64(const char* key, uint64_t fallback) {
    const char* v = std::getenv(key);
    if (v == nullptr || *v == '\0') return fallback;
    try {
        return std::stoull(v);
    } catch (const std::exception&) {
        return fallback;
    }
}

// Windows: по умолчанию папка logs/ с файлом на каждый день (см. README про
// LOG_DIR) — удобно для службы (install-service.bat), где нет консоли, за
// которой можно следить. Иначе (Linux/Docker): stdout/stderr, как и
// положено для контейнеров — раннтайм сам собирает логи с потоков вывода
// процесса, писать в файл внутри контейнера незачем и вредно (пропадёт
// вместе с контейнером).
std::string default_log_dir() {
#ifdef _WIN32
    return "logs";
#else
    return "";
#endif
}

// Читает trace_id, который поставил wallet-gateway (единственная точка
// входа, см. его main.cpp, ensure_trace_id) — сам НИКОГДА не порождает
// новый: если сюда пришёл запрос без X-Trace-Id (прямой curl мимо гейтвея,
// см. ":8080" в README), это ожидаемо и не повод путать логи чужим id.
// Кладёт в thread_local (applog) на время обработки — httplib обслуживает
// запрос от pre_routing_handler до set_logger на одном потоке целиком (см.
// комментарий у set_trace_id в log.hpp).
httplib::Server::HandlerResponse handle_pre_routing(const httplib::Request& req,
                                                     httplib::Response& res) {
    applog::start_request_timer(); // как можно раньше — считаем весь запрос, не только роутинг
    std::string trace_id = req.get_header_value("X-Trace-Id");
    if (!trace_id.empty()) {
        applog::set_trace_id(trace_id);
        res.set_header("X-Trace-Id", trace_id);
    }
    return httplib::Server::HandlerResponse::Unhandled; // только трейс-контекст, роутинг не трогаем
}

} // namespace

int main() {
    fix_console_encoding();
    dotenv::load(".env");

    std::string log_dir = env_or("LOG_DIR", default_log_dir());
    if (log_dir == "stdout" || log_dir == "-") log_dir.clear(); // явно попросили консоль
    applog::init(log_dir, "google-auth");

    // build_info для /metrics (см. util/metrics.cpp) — один раз здесь, до
    // svr.listen() (см. GET /version, docs.cpp — та же тройка полей).
    metrics::set_build_info(version::kService, version::kVersion, version::kGitCommit);

    AppState state;
    state.google_client_id =
        env_required("GOOGLE_CLIENT_ID", "Client ID из Google Cloud Console");
    state.google_client_secret =
        env_required("GOOGLE_CLIENT_SECRET", "Client secret из Google Cloud Console");
    state.redirect_url = env_or("REDIRECT_URL", "http://localhost:8080/auth/google/callback");
    // Доп. redirect_uri, выбираемые динамически по Host/X-Forwarded-Host
    // запроса (см. google.cpp::resolve_redirect_uri, README — "Вход и с
    // localhost, и по LAN одновременно"). redirect_url — тоже разрешённый,
    // добавляем его сюда же явно, чтобы resolve_redirect_uri сверялась с
    // одним набором, а не с полем + набором по отдельности.
    state.allowed_redirect_uris = parse_csv_list(env_or("ALLOWED_REDIRECT_URIS", ""));
    state.allowed_redirect_uris.insert(state.redirect_url);

    std::string jwt_rsa_key_path = env_required(
        "JWT_RSA_PRIVATE_KEY_PATH",
        "путь к PEM-файлу приватного RSA-ключа для подписи своих токенов — сгенерируйте: "
        "openssl genrsa -out jwt_signing_key.pem 2048 (см. README.md)");
    try {
        state.jwt_signing_key = std::make_unique<crypto::RsaSigningKey>(jwt_rsa_key_path);
    } catch (const std::exception& ex) {
        applog::error(ex.what());
        return 1;
    }

    state.cookie_secure = env_bool("COOKIE_SECURE", false);
    state.admin_emails = parse_email_list(env_or("ADMIN_EMAILS", ""));
    state.support_emails = parse_email_list(env_or("SUPPORT_EMAILS", ""));
    // Фолбэк — значения по умолчанию из AppState (см. app_state.hpp), а не
    // магические числа тут же, чтобы дефолт был в одном месте.
    state.access_token_ttl_secs = env_u64("ACCESS_TOKEN_TTL_SECS", state.access_token_ttl_secs);
    state.refresh_token_ttl_secs = env_u64("REFRESH_TOKEN_TTL_SECS", state.refresh_token_ttl_secs);
    // Пусто по умолчанию — используется системное хранилище сертификатов
    // (cpp-httplib подхватывает его сам). Задайте, только если системного
    // доверенного хранилища на машине нет (см. README.md).
    state.ca_bundle_path = env_or("CA_BUNDLE_PATH", "");

    if (!state.ca_bundle_path.empty() && !std::ifstream(state.ca_bundle_path)) {
        applog::error("CA_BUNDLE_PATH указывает на несуществующий файл: " +
                       state.ca_bundle_path + " (см. README.md)");
        return 1;
    }

    std::string database_url = env_required(
        "DATABASE_URL",
        "строка подключения к Postgres, например postgresql://user:password@localhost:5432/dbname");
    // false по умолчанию — параметры SQL-запросов (email и т.п.) не должны
    // молча оседать в логе; включайте только для локальной отладки (см.
    // README.md, "Логирование").
    bool log_sql_params = env_bool("LOG_SQL_PARAMS", false);
    // Доп. имена параметров, чьи значения маскируются в логе SQL "***" (сверх
    // встроенного набора password/token/secret/... — см. builtin_mask_param_names()
    // в db.cpp) — расширяет его, не заменяет; см. README.md, "Логирование".
    auto log_sql_mask_params = parse_csv_list(env_or("LOG_SQL_MASK_PARAMS", ""));
    // DATABASE_POOL_SIZE — сколько соединений держать одновременно (см.
    // db.hpp::Pool) — 8 по умолчанию, тот же дефолт, что у wallet-api/
    // wallet-report.
    int database_pool_size = std::stoi(env_or("DATABASE_POOL_SIZE", "8"));
    // < 1 отдельно от Pool(size == 0) — там size типа std::size_t, и
    // отрицательное int при касте в него стало бы огромным числом.
    if (database_pool_size < 1) {
        applog::error("DATABASE_POOL_SIZE должен быть положительным целым, получено: " +
                      std::to_string(database_pool_size));
        return 1;
    }
    try {
        state.db_pool = std::make_unique<db::Pool>(database_url, static_cast<std::size_t>(database_pool_size),
                                                    log_sql_params, log_sql_mask_params);
        state.db_pool->verify_schema();
    } catch (const std::exception& ex) {
        applog::error(std::string("Postgres: ") + ex.what());
        return 1;
    }

    // Активные access-токены (см. AppState::redis, repo.hpp) — отдельный
    // стор от DATABASE_URL выше, поэтому свой набор переменных, а не общий
    // "URL". Пусто в REDIS_PASSWORD — обычная ситуация для локальной
    // разработки и для контейнера в приватной docker-сети (см. compose.yaml
    // в корне репозитория).
    std::string redis_host = env_or("REDIS_HOST", "127.0.0.1");
    int redis_port = std::stoi(env_or("REDIS_PORT", "6379"));
    std::string redis_password = env_or("REDIS_PASSWORD", "");
    try {
        state.redis = std::make_unique<redis::Client>(redis_host, redis_port, redis_password);
    } catch (const std::exception& ex) {
        applog::error(std::string("Redis: ") + ex.what());
        return 1;
    }

    // Telegram-бот (см. telegram.hpp) — оба необязательны: без них сервис
    // работает как раньше, только эндпоинты связывания отвечают 503.
    state.telegram_bot_username = env_or("TELEGRAM_BOT_USERNAME", "");
    if (!state.telegram_bot_username.empty() && state.telegram_bot_username[0] == '@') {
        state.telegram_bot_username.erase(0, 1);
    }
    state.telegram_service_secret = env_or("TELEGRAM_SERVICE_SECRET", "");
    state.telegram_link_code_ttl_secs =
        env_u64("TELEGRAM_LINK_CODE_TTL_SECS", state.telegram_link_code_ttl_secs);

    std::string host = env_or("HOST", "127.0.0.1");
    int port = std::stoi(env_or("PORT", "8080"));

    httplib::Server svr;
    svr.set_pre_routing_handler(handle_pre_routing);
    google_auth::register_routes(svr, state);
    auth::register_routes(svr, state);
    admin::register_routes(svr, state);
    devices::register_routes(svr, state);
    telegram::register_routes(svr, state);
    docsapi::register_routes(svr); // GET /openapi.yaml, /docs, /healthz, статика /vendor/swagger-ui/*

    // Access-лог: одна строка на запрос (метод, путь, статус ответа). Ещё на
    // том же потоке, что и handle_pre_routing — trace_id (если был) всё ещё
    // в thread_local, попадёт и в эту строку; clear_trace_id() — последнее,
    // что касается его на этом потоке, дальше он уйдёт в пул httplib
    // обслуживать чужой запрос (см. set_trace_id в log.hpp).
    svr.set_logger([](const httplib::Request& req, const httplib::Response& res) {
        // Метрики — на ВСЕ запросы, включая /healthz и сам /metrics: в
        // отличие от access-лога ниже, кардинальность здесь уже ограничена
        // applog::current_route() (см. util/metrics.hpp), а знать RPS/
        // латентность healthcheck'а тоже полезно (отличить "не отвечает
        // вовсе" от "отвечает медленно"). route выставляется каждым
        // хендлером через applog::set_route() — если хендлер (докстраница,
        // /healthz, /metrics) этого не делает, current_route() вернётся
        // пустой, "(unset)" группирует такие запросы одним лейблом.
        metrics::observe_http_request(
            req.method, applog::current_route().empty() ? "(unset)" : applog::current_route(),
            res.status, applog::request_duration_ms());

        // /healthz — не запрос приложения, а probe compose'а (interval 10s,
        // см. compose.yaml) — по логам он не отличим от реального трафика,
        // но забивает их шумом (~8640 строк/сутки на один сервис) без
        // всякой пользы: сама проверка ничего не открывает и не пишет.
        // clear_request_context() всё равно нужен (thread_local не должен
        // утечь в следующий, никак не связанный запрос на этом потоке) —
        // выходим, не пропуская его, а не просто пропускаем обе строки лога.
        // /metrics — то же самое: скрейп Prometheus каждые 15 с, в теле —
        // текст метрик (или gzip), для разбора инцидентов бесполезный.
        if (req.path == "/healthz" || req.path == "/metrics") {
            applog::clear_request_context();
            return;
        }
        // details ДО clear_request_context() — trace_id/route/user_id ещё в
        // thread_local, попадут в эту строку сами (см. write_line в
        // log.cpp), явно передавать не нужно. "event":"request_finished" —
        // машиночитаемая метка ИМЕННО этой строки (не "db query" и не любой
        // другой info/error) — чтобы в Dashboards агрегировать перцентиль/
        // среднее по duration_ms надёжно, а не полагаться на разбор msg
        // (он меняется на каждый вызов: другой path/status).
        applog::info(req.method + " " + req.path + " -> " + std::to_string(res.status),
                     {{"event", "request_finished"}, {"duration_ms", applog::request_duration_ms()}});
        // Отдельной debug-строкой, не полями к строке выше — "request_finished"
        // агрегируют по duration_ms для метрик, подмешивать туда тела запроса/
        // ответа значило бы тащить их в тот же индекс/дашборд. Уровень именно
        // "debug" (см. log.hpp) — тело здесь может нести google id_token,
        // refresh-токен и т.п., а level — как раз то поле, по которому такие
        // строки отфильтровывают из постоянного мониторинга (jq/Loki), не
        // разбирая msg.
        //
        // Но уровень debug на стенде включён, и логи уходят в OpenSearch —
        // тела ручек, которые возят секреты, не пишем вовсе (2026-09-30):
        // одноразовый код связывания Telegram (link-code, exchange) за 10
        // минут жизни даёт привязать ЧУЖОЙ кошелёк к своему чату, токен бота
        // (/internal/telegram/token) — доступ к чужим отчётам, refresh-токены
        // и id_token (/auth/refresh, /auth/logout, /auth/google/mobile) —
        // вход от имени пользователя.
        bool secret_body = req.path.rfind("/internal/", 0) == 0 || req.path == "/auth/telegram/link-code" ||
                           req.path == "/auth/refresh" || req.path == "/auth/logout" ||
                           req.path == "/auth/google/mobile";
        applog::debug(req.method + " " + req.path,
                      {{"event", "request_body"},
                       {"request_body", secret_body ? std::string("(скрыто: секреты)") : truncate_body(req.body)},
                       {"response_body",
                        secret_body ? std::string("(скрыто: секреты)") : loggable_response_body(res)}});
        applog::clear_request_context();
    });

    applog::info("google-auth v" + std::string(version::kVersion) + " (" +
                 std::string(version::kGitCommit) + ") listening on http://" + host + ":" +
                 std::to_string(port) +
                 (log_dir.empty() ? "" : " (логи: " + log_dir + "/)"));
    if (!svr.listen(host, port)) {
        applog::error("не удалось запустить сервер на " + host + ":" + std::to_string(port) +
                      " (порт занят или недоступен?)");
        return 1;
    }
    return 0;
}
