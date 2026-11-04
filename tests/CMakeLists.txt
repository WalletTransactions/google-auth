# Тесты собираются отдельным исполняемым файлом (google_auth_tests), а не
# через `#ifdef TESTING` внутри google_auth.exe, — так рантайм-бинарь службы
# не тащит тестовый код и его символ main() ни в каком виде.
#
# Тестовому бинарю нужны те же .cpp, что и основному: auth.cpp сам по себе
# ссылается на repo::*, а repo.cpp — на db.cpp/redis_client.cpp, поэтому без
# них тестовый экзешник просто не слинкуется (даже если ни один тест не
# доходит до вызова этих функций в рантайме — см. tests/README.md, что
# именно поэтому здесь не протестировано). google.cpp/admin.cpp/pages.cpp/
# main.cpp сюда сознательно не включены — auth.hpp от них не зависит (см. её
# шапку), а main.cpp приносит второй main().
add_executable(google_auth_tests
    test_main.cpp
    test_base64.cpp
    test_crypto.cpp
    test_jwt.cpp
    test_time.cpp
    test_url.cpp
    test_uuid.cpp
    test_dotenv.cpp
    test_types.cpp
    test_token_claims.cpp
    test_auth.cpp
    test_telegram.cpp
    test_mcp_tokens.cpp
    test_token_exchange.cpp

    ${CMAKE_SOURCE_DIR}/src/auth.cpp
    ${CMAKE_SOURCE_DIR}/src/telegram.cpp
    ${CMAKE_SOURCE_DIR}/src/mcp_tokens.cpp
    ${CMAKE_SOURCE_DIR}/src/token_exchange.cpp
    ${CMAKE_SOURCE_DIR}/src/repo.cpp
    ${CMAKE_SOURCE_DIR}/src/db.cpp
    ${CMAKE_SOURCE_DIR}/src/redis_client.cpp
    ${WALLET_COMMON_DIR}/util/base64.cpp
    ${WALLET_COMMON_DIR}/util/crypto.cpp
    ${WALLET_COMMON_DIR}/util/jwt.cpp
    ${WALLET_COMMON_DIR}/util/jwt_claims.cpp
    ${WALLET_COMMON_DIR}/util/metrics.cpp
    ${WALLET_COMMON_DIR}/util/uuid.cpp
    ${CMAKE_SOURCE_DIR}/src/util/url.cpp
    ${WALLET_COMMON_DIR}/util/dotenv.cpp
    ${WALLET_COMMON_DIR}/util/log.cpp
    ${CMAKE_SOURCE_DIR}/src/util/time.cpp
)

target_include_directories(google_auth_tests PRIVATE
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/third_party
    ${WALLET_COMMON_DIR}
)

target_compile_definitions(google_auth_tests PRIVATE
    CPPHTTPLIB_OPENSSL_SUPPORT
    $<$<CXX_COMPILER_ID:MSVC>:_CRT_SECURE_NO_WARNINGS>
)
target_compile_options(google_auth_tests PRIVATE
    $<$<CXX_COMPILER_ID:MSVC>:/utf-8>
)

target_link_libraries(google_auth_tests PRIVATE
    OpenSSL::SSL
    OpenSSL::Crypto
    Threads::Threads
    PostgreSQL::PostgreSQL
)

if(WIN32)
    target_link_libraries(google_auth_tests PRIVATE ws2_32 crypt32)
endif()

add_test(NAME google_auth_unit_tests COMMAND google_auth_tests)
