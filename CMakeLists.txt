cmake_minimum_required(VERSION 3.16)
project(google_auth_cpp CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Общий код сервисов (util/: jwt, jwks, crypto, log, metrics, ...) — копия
# репозитория wallet-common, обновляется его scripts/vendor.sh; руками не править.
set(WALLET_COMMON_DIR ${CMAKE_SOURCE_DIR}/third_party/wallet-common)

find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)
find_package(PostgreSQL REQUIRED)

# Версия приложения — проставляется на билде, не хардкодится в исходниках
# (см. GET /version, src/docs.cpp, и build_info в GET /metrics, src/util/
# metrics.cpp). Единственный источник самого номера — файл VERSION рядом с
# этим CMakeLists.txt (semver, правится руками при релизе); он же копируется
# в Containerfile (COPY VERSION ./), поэтому одинаково читается что при
# нативной сборке (cmake -B build), что при сборке образа.
#
# Git-хэш — ДОПОЛНИТЕЛЬНО к VERSION, не вместо: отличает два билда с одним и
# тем же номером версии между релизами. У сборки ВНУТРИ контейнера своего
# .git нет (Containerfile копирует только исходники, не весь репозиторий) —
# поэтому сначала смотрим на кэш-переменную GIT_COMMIT: её передаёт
# Containerfile (-DGIT_COMMIT=${GIT_COMMIT}, а туда — ARG GIT_COMMIT,
# который в свою очередь снаружи передаёт `podman build --build-arg
# GIT_COMMIT=$(git rev-parse --short HEAD)`, см. compose.yaml). Нативная
# сборка на рабочей машине эту переменную не задаёт — тогда спрашиваем git
# напрямую, репозиторий уже на месте. Не нашли ни то, ни другое — не падаем,
# версия из VERSION всё равно есть, просто без хэша ("unknown").
file(STRINGS ${CMAKE_SOURCE_DIR}/VERSION APP_VERSION_LINES LIMIT_COUNT 1)
list(GET APP_VERSION_LINES 0 APP_VERSION)
string(STRIP "${APP_VERSION}" APP_VERSION)

# Сборка — тег образа (`0.1.1-rc.2`), отдельно от VERSION: по VERSION сверяет
# выкат smoke в wallet-infra deploy.sh. Release передаёт тег через
# --build-arg APP_BUILD (Containerfile → -DAPP_BUILD); сборка без него
# помечается `-dev`, чтобы её не спутать с релизной (GET /version, поле
# build; wallet-gateway openspec/changes/service-versions, design D1/D2).
if(NOT DEFINED APP_BUILD OR "${APP_BUILD}" STREQUAL "")
    set(APP_BUILD "${APP_VERSION}-dev")
endif()

if(NOT DEFINED GIT_COMMIT OR "${GIT_COMMIT}" STREQUAL "")
    find_program(GIT_EXECUTABLE git)
    set(GIT_COMMIT "unknown")
    if(GIT_EXECUTABLE)
        execute_process(
            COMMAND ${GIT_EXECUTABLE} describe --tags --always --dirty --abbrev=8
            WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
            OUTPUT_VARIABLE GIT_COMMIT
            OUTPUT_STRIP_TRAILING_WHITESPACE
            RESULT_VARIABLE GIT_DESCRIBE_RESULT
            ERROR_QUIET
        )
        if(NOT GIT_DESCRIBE_RESULT EQUAL 0 OR "${GIT_COMMIT}" STREQUAL "")
            set(GIT_COMMIT "unknown")
        endif()
    endif()
endif()
message(STATUS "google_auth version: ${APP_VERSION}, build ${APP_BUILD} (${GIT_COMMIT})")

configure_file(
    ${CMAKE_SOURCE_DIR}/src/version.hpp.in
    ${CMAKE_BINARY_DIR}/generated/version.hpp
    @ONLY
)

add_executable(google_auth
    src/main.cpp
    src/auth.cpp
    src/google.cpp
    src/admin.cpp
    src/devices.cpp
    src/telegram.cpp
    src/mcp_tokens.cpp
    src/token_exchange.cpp
    src/pages.cpp
    src/docs.cpp
    src/db.cpp
    src/redis_client.cpp
    src/repo.cpp
    ${WALLET_COMMON_DIR}/util/base64.cpp
    ${WALLET_COMMON_DIR}/util/crypto.cpp
    ${WALLET_COMMON_DIR}/util/jwt.cpp
    ${WALLET_COMMON_DIR}/util/jwt_claims.cpp
    ${WALLET_COMMON_DIR}/util/uuid.cpp
    src/util/url.cpp
    ${WALLET_COMMON_DIR}/util/dotenv.cpp
    ${WALLET_COMMON_DIR}/util/log.cpp
    ${WALLET_COMMON_DIR}/util/metrics.cpp
    ${WALLET_COMMON_DIR}/util/pg_recover.cpp
    src/util/time.cpp
)

target_include_directories(google_auth PRIVATE
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/third_party
    ${WALLET_COMMON_DIR}
    ${CMAKE_BINARY_DIR}/generated
)

# CPPHTTPLIB_OPENSSL_SUPPORT — включаем TLS-клиент cpp-httplib (нужен для
# HTTPS-запросов к Google). _CRT_SECURE_NO_WARNINGS — чтобы MSVC не ругался
# на std::getenv. /utf-8 — чтобы MSVC не перепутал кодировку исходников:
# в коде много кириллицы (сообщения, HTML-страницы), без этого флага MSVC
# может интерпретировать их в системной кодовой странице вместо UTF-8.
target_compile_definitions(google_auth PRIVATE
    CPPHTTPLIB_OPENSSL_SUPPORT
    $<$<CXX_COMPILER_ID:MSVC>:_CRT_SECURE_NO_WARNINGS>
)
target_compile_options(google_auth PRIVATE
    $<$<CXX_COMPILER_ID:MSVC>:/utf-8>
)

target_link_libraries(google_auth PRIVATE
    OpenSSL::SSL
    OpenSSL::Crypto
    Threads::Threads
    PostgreSQL::PostgreSQL
)

if(WIN32)
    # cpp-httplib + OpenSSL на Windows требуют Winsock и доступ к
    # системному хранилищу сертификатов.
    target_link_libraries(google_auth PRIVATE ws2_32 crypt32)

    # Кладём bat-скрипты установки/запуска службы (NSSM) рядом с готовым
    # .exe при каждой сборке — см. scripts/windows/ и README.md.
    add_custom_command(TARGET google_auth POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_directory
                ${CMAKE_SOURCE_DIR}/scripts/windows
                $<TARGET_FILE_DIR:google_auth>
        COMMENT "Копирую scripts/windows/*.bat рядом с google_auth.exe"
    )

    # openapi.yaml + вендоренный Swagger UI — рядом с .exe, та же рабочая
    # директория, что у .env (см. src/docs.cpp — читает их с диска по
    # относительному пути при каждом GET /openapi.yaml, /docs).
    add_custom_command(TARGET google_auth POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
                ${CMAKE_SOURCE_DIR}/openapi.yaml
                $<TARGET_FILE_DIR:google_auth>/openapi.yaml
        COMMENT "Копирую openapi.yaml рядом с google_auth.exe (GET /openapi.yaml, /docs)"
    )
    add_custom_command(TARGET google_auth POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_directory
                ${CMAKE_SOURCE_DIR}/third_party/swagger-ui
                $<TARGET_FILE_DIR:google_auth>/vendor/swagger-ui
        COMMENT "Копирую вендоренный Swagger UI рядом с google_auth.exe (GET /docs)"
    )

    # libpq — динамическая библиотека (libpq.dll), в отличие от OpenSSL,
    # который слинкован статически через find_package(OpenSSL). Без её
    # копии рядом с .exe (и её собственных зависимостей — SSL/i18n) сервис
    # не запустится: "libpq.dll: cannot open shared object file". Список
    # завязан на layout официального установщика PostgreSQL для Windows;
    # если файла нет — просто пропускаем (EXISTS-проверка), не падаем.
    get_filename_component(POSTGRESQL_ROOT_DIR "${PostgreSQL_INCLUDE_DIR}" DIRECTORY)
    set(POSTGRESQL_BIN_DIR "${POSTGRESQL_ROOT_DIR}/bin")
    foreach(_pg_dll libpq.dll libssl-3-x64.dll libcrypto-3-x64.dll libintl-9.dll libiconv-2.dll libwinpthread-1.dll)
        if(EXISTS "${POSTGRESQL_BIN_DIR}/${_pg_dll}")
            add_custom_command(TARGET google_auth POST_BUILD
                COMMAND ${CMAKE_COMMAND} -E copy_if_different
                        "${POSTGRESQL_BIN_DIR}/${_pg_dll}"
                        $<TARGET_FILE_DIR:google_auth>
                COMMENT "Копирую ${_pg_dll} рядом с google_auth.exe"
            )
        endif()
    endforeach()
else()
    # На Linux — соответствующие скрипты для systemd, см. scripts/linux/.
    add_custom_command(TARGET google_auth POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_directory
                ${CMAKE_SOURCE_DIR}/scripts/linux
                $<TARGET_FILE_DIR:google_auth>
        COMMENT "Копирую scripts/linux/*.sh рядом с google_auth"
    )
    add_custom_command(TARGET google_auth POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
                ${CMAKE_SOURCE_DIR}/openapi.yaml
                $<TARGET_FILE_DIR:google_auth>/openapi.yaml
        COMMENT "Копирую openapi.yaml рядом с google_auth (GET /openapi.yaml, /docs)"
    )
    add_custom_command(TARGET google_auth POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_directory
                ${CMAKE_SOURCE_DIR}/third_party/swagger-ui
                $<TARGET_FILE_DIR:google_auth>/vendor/swagger-ui
        COMMENT "Копирую вендоренный Swagger UI рядом с google_auth (GET /docs)"
    )
endif()

# Юнит-тесты (google_auth_tests) — см. tests/README.md, что именно
# покрыто/не покрыто и почему. Не тянет новых внешних зависимостей (те же
# OpenSSL/PostgreSQL, что и сам сервис) — своя минимальная тестовая обвязка,
# без Catch2/GoogleTest, в том же духе, что и весь остальной код (см.
# README.md, "Минимум внешних зависимостей").
option(GOOGLE_AUTH_BUILD_TESTS "Собирать юнит-тесты google_auth_tests" ON)
if(GOOGLE_AUTH_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

# mint_loadtest_token — разовый CLI для нагрузочного контура wallet-report
# (см. wallet-report/loadtest/README.md и tools/mint_loadtest_token.cpp
# у самого себя): печатает валидный RS256-токен, подписанный ТЕМ ЖЕ кодом,
# что и сам сервис (util/crypto.cpp::RsaSigningKey + util/jwt.cpp::sign_rs256),
# без db.cpp/redis_client.cpp/repo.cpp — токену не нужна ни БД, ни Redis,
# только приватный ключ.
option(GOOGLE_AUTH_BUILD_LOADTEST_TOOLS
       "Собирать mint_loadtest_token для нагрузочного контура wallet-report" OFF)
if(GOOGLE_AUTH_BUILD_LOADTEST_TOOLS)
    add_executable(mint_loadtest_token
        tools/mint_loadtest_token.cpp
        ${WALLET_COMMON_DIR}/util/base64.cpp
        ${WALLET_COMMON_DIR}/util/crypto.cpp
        ${WALLET_COMMON_DIR}/util/jwt.cpp
        src/util/time.cpp
    )

    target_include_directories(mint_loadtest_token PRIVATE
        ${CMAKE_SOURCE_DIR}/src
        ${CMAKE_SOURCE_DIR}/third_party
        ${WALLET_COMMON_DIR}
    )

    target_compile_definitions(mint_loadtest_token PRIVATE
        $<$<CXX_COMPILER_ID:MSVC>:_CRT_SECURE_NO_WARNINGS>
    )
    target_compile_options(mint_loadtest_token PRIVATE
        $<$<CXX_COMPILER_ID:MSVC>:/utf-8>
    )

    target_link_libraries(mint_loadtest_token PRIVATE
        OpenSSL::Crypto
    )
endif()
