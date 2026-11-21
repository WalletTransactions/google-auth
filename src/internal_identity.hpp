// Идентичность вызывающего на /internal/* по клиентскому сертификату (change
// add-internal-mtls в wallet-infra, design D4 и D12).
//
// Сертификат отвечает на вопрос «КАКОЙ сервис вызывает», секрет или токен в
// запросе — «ЗА кого». Проверка идёт вместе с секретом, а не вместо него.
//
// Режимы, на каждую группу ручек отдельно (чтобы переносить клиентов по одному):
//   off         — проверок нет (по умолчанию);
//   observe     — запрос принимается как раньше, но каждое расхождение (нет
//                 сертификата, сервис не из списка, CN не равен actor по секрету)
//                 уходит в журнал и метрику;
//   enforce-tls — отказ 403 при отсутствии сертификата и при CN != actor;
//   enforce     — то же, и отказ, если CN не в списке разрешённых для ручки.
//
// Настройка INTERNAL_IDENTITY: «observe» (для всех групп) или с исключениями:
// «observe,telegram=enforce,exchange=observe». Группы: telegram
// (/internal/telegram/*), mcp-token (/internal/mcp/token), exchange
// (/internal/token/exchange).
#pragma once

#include <map>
#include <optional>
#include <string>
#include <vector>

namespace httplib {
struct Request;
struct Response;
} // namespace httplib

namespace internal_identity {

enum class Mode { Off, Observe, EnforceTls, Enforce };

enum class Finding { Ok, NoCert, Forbidden, ActorMismatch };

const char* mode_name(Mode mode);
const char* finding_name(Finding finding);

struct Config {
    Mode default_mode = Mode::Off;
    std::map<std::string, Mode> by_group;

    Mode mode_for(const std::string& group) const {
        auto it = by_group.find(group);
        return it != by_group.end() ? it->second : default_mode;
    }
    bool any_enabled() const {
        if (default_mode != Mode::Off) return true;
        for (const auto& kv : by_group) {
            if (kv.second != Mode::Off) return true;
        }
        return false;
    }
};

// Разбор INTERNAL_IDENTITY. Пустая строка — всё off. Неизвестный режим или группа —
// nullopt и текст в error (молча выключенная проверка хуже отказа на старте).
std::optional<Config> parse_config(const std::string& text, std::string* error = nullptr);

// Группа по пути запроса; пусто — путь не служебный.
std::string group_of(const std::string& path);

// Кому разрешена группа (design D4).
const std::vector<std::string>& allowed_services(const std::string& group);

struct Verdict {
    Finding finding = Finding::Ok;
    bool reject = false;
};

// Чистые решения (юнит-тесты). peer_cn пуст — сертификата нет.
Verdict judge_rights(Mode mode, const std::string& group, const std::string& peer_cn);
Verdict judge_actor(Mode mode, const std::string& peer_cn, const std::string& actor);

// Применение к запросу: журнал, метрика, при отказе — 403 и false (ответ уже записан).
// check_rights — в начале ручки, ДО проверки секрета; check_actor — после того, как
// actor определён по секрету.
bool check_rights(const Config& cfg, const httplib::Request& req, httplib::Response& res);
bool check_actor(const Config& cfg, const httplib::Request& req, httplib::Response& res,
                 const std::string& actor);

} // namespace internal_identity
