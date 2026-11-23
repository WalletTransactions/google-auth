// pages::error: текст ошибки приходит из ?error= callback'а Google и из
// ответов Google — на странице он обязан быть экранирован (reflected XSS на
// origin кабинета, gateway проксирует /auth/*).
#include "pages.hpp"

#include "test_framework.hpp"

TEST(pages_error_escapes_markup_in_message) {
    std::string html = pages::error("<script>alert(1)</script>\"'&");
    CHECK(html.find("<script>alert") == std::string::npos);
    CHECK(html.find("&lt;script&gt;alert(1)&lt;/script&gt;&quot;&#39;&amp;") != std::string::npos);
}

TEST(pages_error_keeps_plain_text) {
    std::string html = pages::error("Google вернул ошибку авторизации: access_denied");
    CHECK(html.find("Google вернул ошибку авторизации: access_denied") != std::string::npos);
}
