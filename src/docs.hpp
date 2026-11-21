// Отдаёт собственную OpenAPI-спеку сервиса (openapi.yaml, "Зеркало
// openapi.yaml следует за API" — правится в том же заходе, что и сам роут,
// см. src/wallet.cpp/sync.cpp/blob.cpp) и Swagger UI поверх неё (GET /docs),
// чтобы описание методов и живую форму для вызовов не нужно было носить
// отдельно от сервиса. Swagger UI — вендоренный статический бандл
// (third_party/swagger-ui/, см. его README — версия/происхождение), не
// CDN-ссылка: сервис должен отдавать документацию и без доступа наружу (см.
// org/docs/TODO_mobile_sync.md, "LAN-only MVP").
//
// Чисто статика, без авторизации — то же самое, что curl openapi.yaml,
// только с интерактивной формой (кнопка Authorize в /docs подставляет
// Authorization: Bearer в реальные вызовы "Try it out").
//
// openapi.yaml и third_party/swagger-ui/ читаются С ДИСКА по относительному
// пути (рабочая директория — папка рядом с исполняемым файлом, та же, где
// .env — см. scripts/windows/run-console.bat) — CMakeLists.txt копирует туда
// оба при каждой сборке (POST_BUILD), Containerfile — при сборке образа.
#pragma once

#include "httplib.h"

namespace docsapi {

// with_service_routes=false — /healthz и /metrics не регистрируются (их отдаёт служебный mTLS-слушатель,
// SERVICE_MTLS_PORT; change add-internal-mtls, задача 8.3); /version остаётся публичным.
void register_routes(httplib::Server& svr, bool with_service_routes = true);

// Только /healthz, /metrics и /version — для служебного mTLS-слушателя.
void register_service_routes(httplib::Server& svr);

} // namespace docsapi
