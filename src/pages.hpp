// HTML-страницы (браузерная часть флоу) — только то немногое, что всё ещё
// рендерит сам этот сервис: index (fallback при прямом заходе, минуя
// гейтвей и SPA), подтверждение регистрации, ошибка. Список пользователей
// (/admin/users) сюда больше не входит — переехал в SPA как JSON API (см.
// admin.cpp и ../wallet-web/site/app.js, renderAdmin()); эти три страницы
// остались HTML не по недосмотру, а потому что все они — прямой ответ на
// серверный редирект от Google/браузера ДО того, как JS SPA вообще успевает
// загрузиться (см. README, "Структура").
// Основной UI после логина — SPA (см. ../wallet-web); success-страницы
// больше нет — после логина сервис делает redirect на "/", см. google.cpp.
// Общий CSS теперь тоже не здесь — все шаблоны ссылаются на
// GET /style.css (см. ../wallet-web/site/style.css), а не встраивают
// <style> инлайном — резолвится, только если страница открыта через
// гейтвей (см. README ../wallet-web, "Маршрутизация через гейтвей").
#pragma once

#include <string>

#include "types.hpp"

namespace pages {

std::string index();

std::string error(const std::string& message);

// Показывается вместо тихого автосоздания аккаунта, когда Google подтвердил
// личность, но такого google_sub ещё нет в users. confirm_token —
// одноразовый ключ в AppState::pending_signups, уходит скрытым полем формы
// на POST /auth/google/confirm-signup. name/email — из Google, экранируются
// перед вставкой в HTML (см. html_escape() в .cpp) — это чужой ввод, доверять
// ему как готовой разметке нельзя.
std::string confirm_signup(const PendingSignup& pending, const std::string& confirm_token);

} // namespace pages
