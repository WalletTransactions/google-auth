// Простые структуры данных без какой-либо логики — чтобы их могли включать
// и app_state.hpp, и pages.hpp, не образуя циклических зависимостей с
// google.hpp/auth.hpp (см. пояснение в app_state.hpp).
#pragma once

#include <cstdint>
#include <string>

// Три уровня, по возрастанию прав. Раньше (пока CRUD кошельков жил в этом же
// сервисе) разница была расписана в терминах доступа к чужим кошелькам —
// это переехало вместе с ним в ../wallet-api (там своя, гораздо более узкая
// модель прав — см. его README). Здесь роль сейчас используется только для
// admin.* (доступ к /admin/users) и передаётся дальше в payload access-токена
// — другие сервисы (в т.ч. wallet-api) могут прочитать её из claim'а `role`,
// если им это понадобится.
// User    — обычный пользователь, без доступа к /admin/*.
// Support — зарезервировано для read-only доступа поддержки (пока нигде,
//           кроме claim'а токена, не проверяется).
// Admin   — доступ к /admin/users (см. admin.cpp).
enum class Role {
    User,
    Support,
    Admin,
};

inline const char* to_string(Role r) {
    switch (r) {
        case Role::Admin: return "admin";
        case Role::Support: return "support";
        case Role::User: default: return "user";
    }
}

// Неизвестная/отсутствующая строка -> User (минимум привилегий по умолчанию).
inline Role role_from_string(const std::string& s) {
    if (s == "admin") return Role::Admin;
    if (s == "support") return Role::Support;
    return Role::User;
}

// Id роли в справочнике roles(id) — см. infra/db/init-db.sh в корне репозитория
// (там же и seed-данные этой таблицы, той же тройкой строк — id, code,
// description). Значения зафиксированы и НЕ автоинкремент: они зашиты и
// здесь, и в seed-данных таблицы — менять их можно только синхронно в
// обоих местах.
inline int16_t to_role_id(Role r) {
    switch (r) {
        case Role::Admin: return 3;
        case Role::Support: return 2;
        case Role::User: default: return 1;
    }
}

// Неизвестный id -> User, тем же принципом минимума привилегий, что и
// role_from_string().
inline Role role_from_id(int16_t id) {
    switch (id) {
        case 3: return Role::Admin;
        case 2: return Role::Support;
        default: return Role::User;
    }
}

struct UserRecord {
    std::string id;           // внутренний UUID v4 — не зависит от формата Google-ID
    std::string google_sub;   // ключ для поиска при повторном логине через Google
    std::string email;
    bool email_verified = false;
    std::string name;
    std::string picture;      // пусто, если аватара нет

    // Момент первого входа (users.created_at, проставляется Postgres'ом
    // через DEFAULT now() при INSERT, дальше не меняется) — как есть,
    // текстом из БД (см. row_to_user в repo.cpp), не std::chrono: этому коду
    // достаточно значения для показа в админ-таблице, не для арифметики
    // над ним.
    std::string created_at;
    // Момент ПОСЛЕДНЕГО входа (users.last_login_at, миграция 000003) — в
    // отличие от created_at, обновляется repo::upsert_user на КАЖДЫЙ логин.
    // Пусто (SQL NULL) у строк, заведённых до этой колонки и ни разу не
    // логинившихся после — не выдумываем дату, которой не знаем.
    std::string last_login_at;

    // Вычисляется из ADMIN_EMAILS/SUPPORT_EMAILS (см. AppState) только один
    // раз — при первом логине этого пользователя (см.
    // repo::upsert_user — role_id не трогается при повторных логинах уже
    // существующего). Дальше это авторизационное состояние, а не профильные
    // данные из Google — меняется только явной правкой users.role_id в БД.
    Role role = Role::User;
};

// Данные из верифицированного Google id_token для человека, которого ещё
// нет в users — ждут явного подтверждения на POST /auth/google/confirm-signup
// (см. google.cpp), храним в AppState::pending_signups. Копия полей
// GoogleClaims (google.hpp), а не сам этот тип — types.hpp специально не
// зависит от google.hpp (см. шапку файла).
struct PendingSignup {
    std::string google_sub;
    std::string email;
    bool email_verified = false;
    std::string name;
    std::string picture;
};

// Устройство/клиент, которому выпущена пара токенов — заполняется в
// google.cpp (браузер — из User-Agent, мобильный вход — из тела запроса) и
// сопровождает refresh-токен всю его жизнь: рефреш переносит эти же поля на
// новую пару (см. auth::rotate_refresh_token), поэтому "какое это
// устройство" не теряется при каждой ротации. Непустой `device_id` кладётся
// ещё и в сам access-JWT (claim `device_id`, см. auth.cpp) — так wallet-api
// получает id устройства уже ПРОВЕРЕННЫМ подписью, а не из произвольного
// клиентского заголовка (см. org/docs/TODO_mobile_sync.md, п. 1.2).
//
// Все поля опциональны и пусты по умолчанию — браузерный логин не обязан
// передавать `device_id` (у браузера нет естественного стабильного
// идентификатора устройства, только сессия).
// Допустимые значения DeviceInfo::platform в теле POST /auth/google/mobile
// — подмножество CHECK device.platform в wallet-api (миграция
// wallet/000023): иначе клиент с произвольной строкой получил бы валидный
// токен, а первый же /sync/* — 500 на нарушении ограничения. "telegram" сюда
// намеренно не входит: такую сессию выдаёт только обмен кода связывания
// (telegram.cpp), не вход через Google.
inline bool is_mobile_login_platform(const std::string& p) {
    return p == "android" || p == "ios" || p == "web" || p == "other";
}

struct DeviceInfo {
    std::string device_id;    // генерирует клиент один раз, хранит локально (Android — AppSettings)
    std::string device_name;  // "Pixel 7" / сырой User-Agent браузера — только для показа человеку
    std::string platform;     // "android" / "web" / ...
};
