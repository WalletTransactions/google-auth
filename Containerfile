# syntax=docker/dockerfile:1
#
# Multi-stage build google-auth-cpp. Собираем в debian:bookworm-slim с
# build-essential/cmake/libssl-dev/libpq-dev, в рантайм-образ кладём только
# сам бинарник + разделяемые библиотеки (libssl3, libpq5) + ca-certificates
# (нужен для HTTPS-запросов к Google, см. README "cpp-httplib сам использует
# системное хранилище сертификатов") + curl (нужен ТОЛЬКО healthcheck'у в
# compose.yaml — сам образ debian:bookworm-slim его не содержит).
#
# third_party/ (httplib.h, nlohmann) — header-only, копируются исходниками,
# отдельно ставить не нужно.

FROM debian:bookworm-slim AS build

# GIT_COMMIT — короткий хэш коммита (git rev-parse --short HEAD/git describe
# на хосте, где ЕСТЬ .git — у этой стадии своего нет, .git в контекст сборки
# не входит), передаётся снаружи через `podman build --build-arg
# GIT_COMMIT=...` (см. compose.yaml). Не передали — CMakeLists.txt сам
# попробует спросить git и, если не найдёт, поставит "unknown" (версия из
# VERSION при этом всё равно на месте, см. CMakeLists.txt, "Версия
# приложения").
ARG GIT_COMMIT=unknown

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        cmake \
        libssl-dev \
        libpq-dev \
        pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY CMakeLists.txt ./
COPY VERSION ./
COPY openapi.yaml ./
COPY src/ src/
COPY third_party/ third_party/
COPY scripts/ scripts/
# ^ нужен: CMakeLists.txt в Linux-ветке копирует scripts/linux/*.sh рядом с
#   бинарником через POST_BUILD add_custom_command (copy_directory), без
#   EXISTS-проверки — без этой папки в контексте сборка упадёт. openapi.yaml
#   рядом по той же причине — тот же POST_BUILD копирует и её
#   (copy_if_different ${CMAKE_SOURCE_DIR}/openapi.yaml, см. CMakeLists.txt) —
#   без этой строки сборка стадии build падала на "no such file or directory"
#   ("Error copying file (if different)"), хотя runtime-стадия ниже эту же
#   openapi.yaml берёт напрямую из контекста, а не из стадии build.

# tests/ сюда нарочно НЕ копируется (образу рантайма юнит-тесты не нужны) —
# поэтому GOOGLE_AUTH_BUILD_TESTS=OFF обязателен: по умолчанию (ON, см.
# CMakeLists.txt) configure упал бы на add_subdirectory(tests) с "not an
# existing directory". Тот же флаг, что описан в tests/README.md для случая
# "нет OpenSSL/PostgreSQL под тесты" — здесь причина та же по сути (тестового
# окружения в этом образе просто нет).
RUN cmake -B build -DCMAKE_BUILD_TYPE=Release -DGOOGLE_AUTH_BUILD_TESTS=OFF \
        -DGIT_COMMIT="${GIT_COMMIT}" \
    && cmake --build build --config Release -j"$(nproc)"

FROM debian:bookworm-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        libssl3 \
        libpq5 \
        curl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --create-home --home-dir /app --shell /usr/sbin/nologin appuser

WORKDIR /app
COPY --from=build /src/build/google_auth /app/google_auth
# openapi.yaml + вендоренный Swagger UI — читаются с диска по относительному
# пути при каждом GET /openapi.yaml, /docs (см. src/docs.cpp) — чистая
# статика, копируется прямо из контекста сборки, без стадии build.
COPY openapi.yaml /app/openapi.yaml
COPY third_party/swagger-ui/ /app/vendor/swagger-ui/

# LOG_DIR не задан -> util/log.cpp пишет в stdout/stderr на Linux (см. README,
# раздел "Логирование") — это и есть ожидаемое поведение в контейнере.
# JWT_RSA_PRIVATE_KEY_PATH указывает на файл, который нужно смонтировать
# отдельно (см. compose.yaml) — приватный ключ в образ не кладём.
USER appuser
EXPOSE 8080

ENTRYPOINT ["/app/google_auth"]
