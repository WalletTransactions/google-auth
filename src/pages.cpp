#include "pages.hpp"

#include <unordered_map>

namespace pages {

namespace {

// Email/имя пользователя приходят от Google — доверять им как готовой
// HTML-разметке нельзя. Нужен для confirm_signup(): единственного места в
// этом файле, где во вставляемых значениях есть символы, которые могли бы
// сломать разметку или дать XSS ('&', '<', '>', '"').
std::string html_escape(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (char c : s) {
        switch (c) {
            case '&': out += "&amp;"; break;
            case '<': out += "&lt;"; break;
            case '>': out += "&gt;"; break;
            case '"': out += "&quot;"; break;
            default: out += c;
        }
    }
    return out;
}

std::string render(std::string tmpl, const std::unordered_map<std::string, std::string>& vars) {
    for (const auto& [key, value] : vars) {
        std::string placeholder = "{{" + key + "}}";
        size_t pos = 0;
        while ((pos = tmpl.find(placeholder, pos)) != std::string::npos) {
            tmpl.replace(pos, placeholder.size(), value);
            pos += value.size();
        }
    }
    return tmpl;
}

} // namespace

std::string index() {
    static const char* tmpl = R"HTML(<!doctype html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Вход через Google</title>
<link rel="icon" href="/favicon.svg">
<link rel="stylesheet" href="/style.css">
</head>
<body>
  <div class="card">
    <h1>Проверка Google-аккаунта</h1>
    <p class="sub">Нажмите кнопку ниже, чтобы войти через свою Google-учётную запись.
    Сервер проверит подпись токена и покажет, кто вы.</p>
    <a class="google-btn" href="/auth/google">
      <svg width="18" height="18" viewBox="0 0 48 48" aria-hidden="true">
        <path fill="#FFC107" d="M43.6 20.5H42V20H24v8h11.3c-1.6 4.7-6.1 8-11.3 8-6.6 0-12-5.4-12-12s5.4-12 12-12c3.1 0 5.9 1.2 8 3.1l5.7-5.7C34.6 6.1 29.6 4 24 4 12.9 4 4 12.9 4 24s8.9 20 20 20 20-8.9 20-20c0-1.3-.1-2.7-.4-3.5z"/>
        <path fill="#FF3D00" d="M6.3 14.7l6.6 4.8C14.6 15.9 18.9 13 24 13c3.1 0 5.9 1.2 8 3.1l5.7-5.7C34.6 6.1 29.6 4 24 4 16.3 4 9.7 8.3 6.3 14.7z"/>
        <path fill="#4CAF50" d="M24 44c5.5 0 10.4-1.9 14.3-5.1l-6.6-5.6C29.6 35 26.9 36 24 36c-5.2 0-9.6-3.3-11.3-7.9l-6.6 5.1C9.6 39.6 16.3 44 24 44z"/>
        <path fill="#1976D2" d="M43.6 20.5H42V20H24v8h11.3c-.8 2.3-2.3 4.3-4.2 5.7l6.6 5.6C41.5 36.4 44 30.6 44 24c0-1.3-.1-2.7-.4-3.5z"/>
      </svg>
      Войти через Google
    </a>
    <p class="sub-id">Обычно эту страницу не видно — гейтвей открывает
    вместо неё SPA (wallet-web). Вы попали сюда либо в обход гейтвея,
    напрямую на :8080, либо app.js не смог получить /auth/me.</p>
  </div>
</body>
</html>)HTML";
    return render(tmpl, {});
}

std::string error(const std::string& message) {
    static const char* tmpl = R"HTML(<!doctype html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Ошибка входа</title>
<link rel="icon" href="/favicon.svg">
<link rel="stylesheet" href="/style.css">
</head>
<body>
  <div class="card">
    <h1>Не удалось войти</h1>
    <p class="err">{{MESSAGE}}</p>
    <a class="btn" href="/">Попробовать снова</a>
  </div>
</body>
</html>)HTML";
    return render(tmpl, {{"MESSAGE", message}});
}

std::string confirm_signup(const PendingSignup& pending, const std::string& confirm_token) {
    std::string avatar_html;
    if (!pending.picture.empty()) {
        // src — атрибут, а не текстовый узел: html_escape() экранирует и
        // кавычку ('"' -> "&quot;"), этого достаточно, чтобы значение не
        // вырвалось из атрибута, даже если URL пришёл с кавычкой внутри.
        avatar_html = "<img class=\"avatar\" src=\"" + html_escape(pending.picture) + "\" alt=\"avatar\">";
    }
    std::string name = pending.name.empty() ? "Пользователь" : pending.name;

    static const char* tmpl = R"HTML(<!doctype html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Создать аккаунт?</title>
<link rel="icon" href="/favicon.svg">
<link rel="stylesheet" href="/style.css">
</head>
<body>
  <div class="card">
    {{AVATAR}}
    <h1>Аккаунт не найден</h1>
    <p class="sub">Google подтвердил, что это вы — {{NAME}} ({{EMAIL}}) — но учётной записи
    с этим Google-аккаунтом в системе ещё нет. Создать новую?</p>
    <div class="actions-row">
      <form method="POST" action="/auth/google/confirm-signup">
        <input type="hidden" name="token" value="{{TOKEN}}">
        <button type="submit" class="btn">Создать аккаунт</button>
      </form>
      <a class="btn btn-secondary" href="/">Отмена</a>
    </div>
  </div>
</body>
</html>)HTML";

    return render(tmpl, {
                             {"AVATAR", avatar_html},
                             // name/email — из Google, но это тот же самый
                             // Google-аккаунт, что сейчас смотрит на эту
                             // страницу (не чужие данные, как в бывшей
                             // admin_users()) — экранируем всё равно: имя в
                             // Google можно менять свободно, включая на
                             // произвольную строку с HTML-спецсимволами.
                             {"NAME", html_escape(name)},
                             {"EMAIL", html_escape(pending.email)},
                             {"TOKEN", html_escape(confirm_token)},
                         });
}

} // namespace pages
