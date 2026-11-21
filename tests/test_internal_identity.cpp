// Идентичность вызывающего на /internal/* (change add-internal-mtls, задача 4.1):
// режимы observe / enforce-tls / enforce по группам, таблица прав D4, сверка CN с actor.
// Чистые решения проверяются таблицей; применение к запросу — через настоящий mTLS-сервер.
#include "internal_identity.hpp"

#include <algorithm>

#include "httplib.h"
#include "test_framework.hpp"
#include "tls_test_util.hpp"

using namespace tlstest;
namespace ii = internal_identity;

TEST(ii_parse_empty_is_all_off) {
    auto cfg = ii::parse_config("");
    REQUIRE(cfg.has_value());
    CHECK(!cfg->any_enabled());
    CHECK(cfg->mode_for("telegram") == ii::Mode::Off);
}

TEST(ii_parse_default_and_group_override) {
    auto cfg = ii::parse_config("observe,telegram=enforce, exchange=enforce-tls");
    REQUIRE(cfg.has_value());
    CHECK(cfg->mode_for("mcp-token") == ii::Mode::Observe);
    CHECK(cfg->mode_for("telegram") == ii::Mode::Enforce);
    CHECK(cfg->mode_for("exchange") == ii::Mode::EnforceTls);
    CHECK(cfg->any_enabled());
}

TEST(ii_parse_only_group_keeps_default_off) {
    auto cfg = ii::parse_config("telegram=observe");
    REQUIRE(cfg.has_value());
    CHECK(cfg->mode_for("telegram") == ii::Mode::Observe);
    CHECK(cfg->mode_for("exchange") == ii::Mode::Off);
}

TEST(ii_parse_rejects_garbage) {
    std::string err;
    CHECK(!ii::parse_config("sometimes", &err).has_value());
    CHECK(!err.empty());
    CHECK(!ii::parse_config("observe,nosuch=enforce", &err).has_value());
    CHECK(!ii::parse_config("telegram=maybe", &err).has_value());
    // режим по умолчанию — только первым
    CHECK(!ii::parse_config("telegram=observe,enforce", &err).has_value());
}

TEST(ii_group_of_paths) {
    CHECK_EQ(ii::group_of("/internal/telegram/token"), std::string("telegram"));
    CHECK_EQ(ii::group_of("/internal/telegram/links/42"), std::string("telegram"));
    CHECK_EQ(ii::group_of("/internal/mcp/token"), std::string("mcp-token"));
    CHECK_EQ(ii::group_of("/internal/token/exchange"), std::string("exchange"));
    CHECK_EQ(ii::group_of("/auth/refresh"), std::string(""));
}

TEST(ii_default_rights_table_matches_design_d4) {
    CHECK_EQ(ii::allowed_services("telegram").size(), static_cast<size_t>(1));
    CHECK_EQ(ii::allowed_services("telegram")[0], std::string("wallet-telegram"));
    auto mcp = ii::allowed_services("mcp-token");
    CHECK(std::find(mcp.begin(), mcp.end(), "wallet-mcp") != mcp.end());
    CHECK(std::find(mcp.begin(), mcp.end(), "wallet-ai") != mcp.end());
    CHECK(std::find(mcp.begin(), mcp.end(), "wallet-telegram") == mcp.end());
    auto ex = ii::allowed_services("exchange");
    CHECK_EQ(ex.size(), static_cast<size_t>(3));
}

TEST(ii_rights_off_never_judges) {
    auto v = ii::judge_rights(ii::Mode::Off, "telegram", "");
    CHECK(v.finding == ii::Finding::Ok);
    CHECK(!v.reject);
}

TEST(ii_rights_observe_flags_but_never_rejects) {
    auto none = ii::judge_rights(ii::Mode::Observe, "telegram", "");
    CHECK(none.finding == ii::Finding::NoCert);
    CHECK(!none.reject);
    auto foreign = ii::judge_rights(ii::Mode::Observe, "telegram", "wallet-api");
    CHECK(foreign.finding == ii::Finding::Forbidden);
    CHECK(!foreign.reject);
    auto fine = ii::judge_rights(ii::Mode::Observe, "telegram", "wallet-telegram");
    CHECK(fine.finding == ii::Finding::Ok);
}

TEST(ii_rights_enforce_tls_rejects_missing_cert_only) {
    CHECK(ii::judge_rights(ii::Mode::EnforceTls, "telegram", "").reject);
    // чужой сервис с действительным сертификатом в этом режиме ещё проходит (но помечен)
    auto foreign = ii::judge_rights(ii::Mode::EnforceTls, "telegram", "wallet-api");
    CHECK(foreign.finding == ii::Finding::Forbidden);
    CHECK(!foreign.reject);
}

TEST(ii_rights_enforce_rejects_foreign_service) {
    auto foreign = ii::judge_rights(ii::Mode::Enforce, "telegram", "wallet-api");
    CHECK(foreign.finding == ii::Finding::Forbidden);
    CHECK(foreign.reject);
    CHECK(ii::judge_rights(ii::Mode::Enforce, "telegram", "").reject);
    CHECK(!ii::judge_rights(ii::Mode::Enforce, "telegram", "wallet-telegram").reject);
}

TEST(ii_actor_mismatch_is_flagged_and_rejected_from_enforce_tls) {
    // сертификат wallet-mcp, секрет wallet-ai
    auto obs = ii::judge_actor(ii::Mode::Observe, "wallet-mcp", "wallet-ai");
    CHECK(obs.finding == ii::Finding::ActorMismatch);
    CHECK(!obs.reject);
    CHECK(ii::judge_actor(ii::Mode::EnforceTls, "wallet-mcp", "wallet-ai").reject);
    CHECK(ii::judge_actor(ii::Mode::Enforce, "wallet-mcp", "wallet-ai").reject);
    CHECK(ii::judge_actor(ii::Mode::Enforce, "wallet-ai", "wallet-ai").finding == ii::Finding::Ok);
}

TEST(ii_actor_without_certificate_is_not_counted_twice) {
    // «нет сертификата» уже отмечено на этапе прав
    CHECK(ii::judge_actor(ii::Mode::Enforce, "", "wallet-ai").finding == ii::Finding::Ok);
    CHECK(ii::judge_actor(ii::Mode::Enforce, "wallet-ai", "").finding == ii::Finding::Ok);
}

namespace {

// Сервер с маршрутом, который ведёт себя как ручка: права, затем actor из заголовка X-Test-Actor.
void routes(httplib::Server& svr, const ii::Config& cfg) {
    svr.Post("/internal/telegram/token", [&cfg](const httplib::Request& req, httplib::Response& res) {
        if (!ii::check_rights(cfg, req, res)) return;
        res.set_content("ok", "text/plain");
    });
    svr.Post("/internal/token/exchange", [&cfg](const httplib::Request& req, httplib::Response& res) {
        if (!ii::check_rights(cfg, req, res)) return;
        if (!ii::check_actor(cfg, req, res, req.get_header_value("X-Test-Actor"))) return;
        res.set_content("ok", "text/plain");
    });
}

struct Fixture {
    Dir dir;
    std::unique_ptr<Pem> ca = issue("ca", "", nullptr);
    std::unique_ptr<Pem> srv = issue("google-auth-internal", "IP:127.0.0.1", ca.get());

    std::unique_ptr<Pem> client(const std::string& cn) { return issue(cn, "DNS:" + cn, ca.get()); }
};

int status_of(const nettls::Config& client_cfg, int port, const std::string& path,
              const std::string& actor = "") {
    auto cli = nettls::make_client(url(port), client_cfg);
    if (!cli) return -1;
    httplib::Headers h;
    if (!actor.empty()) h.emplace("X-Test-Actor", actor);
    auto res = cli->Post(path, h, "", "text/plain");
    return res ? res->status : 0;
}

} // namespace

TEST(ii_enforce_over_mtls_allows_telegram_and_forbids_other_services) {
    Fixture f;
    ii::Config cfg;
    cfg.default_mode = ii::Mode::Enforce;
    Running run(nettls::make_server(files(f.dir, "srv", *f.srv, *f.ca)),
                [&cfg](httplib::Server& s) { routes(s, cfg); });

    auto tg = f.client("wallet-telegram");
    auto api = f.client("wallet-api");
    CHECK_EQ(status_of(files(f.dir, "tg", *tg, *f.ca), run.port(), "/internal/telegram/token"), 200);
    CHECK_EQ(status_of(files(f.dir, "api", *api, *f.ca), run.port(), "/internal/telegram/token"), 403);
}

TEST(ii_observe_over_mtls_lets_everything_through) {
    Fixture f;
    ii::Config cfg;
    cfg.default_mode = ii::Mode::Observe;
    Running run(nettls::make_server(files(f.dir, "srv", *f.srv, *f.ca)),
                [&cfg](httplib::Server& s) { routes(s, cfg); });

    auto api = f.client("wallet-api");
    CHECK_EQ(status_of(files(f.dir, "api", *api, *f.ca), run.port(), "/internal/telegram/token"), 200);
}

TEST(ii_group_modes_are_independent) {
    Fixture f;
    ii::Config cfg;
    cfg.default_mode = ii::Mode::Observe;
    cfg.by_group["telegram"] = ii::Mode::Enforce;
    Running run(nettls::make_server(files(f.dir, "srv", *f.srv, *f.ca)),
                [&cfg](httplib::Server& s) { routes(s, cfg); });

    auto mcp = f.client("wallet-mcp");
    auto mcp_cfg = files(f.dir, "mcp", *mcp, *f.ca);
    CHECK_EQ(status_of(mcp_cfg, run.port(), "/internal/telegram/token"), 403); // telegram — enforce
    CHECK_EQ(status_of(mcp_cfg, run.port(), "/internal/token/exchange", "wallet-mcp"), 200); // exchange — observe
}

TEST(ii_exchange_certificate_and_secret_from_different_services_is_rejected) {
    Fixture f;
    ii::Config cfg;
    cfg.default_mode = ii::Mode::Enforce;
    Running run(nettls::make_server(files(f.dir, "srv", *f.srv, *f.ca)),
                [&cfg](httplib::Server& s) { routes(s, cfg); });

    auto mcp = f.client("wallet-mcp");
    auto mcp_cfg = files(f.dir, "mcp", *mcp, *f.ca);
    CHECK_EQ(status_of(mcp_cfg, run.port(), "/internal/token/exchange", "wallet-mcp"), 200);
    // сертификат wallet-mcp, секрет wallet-ai
    CHECK_EQ(status_of(mcp_cfg, run.port(), "/internal/token/exchange", "wallet-ai"), 403);
}

TEST(ii_plain_request_is_rejected_only_when_group_enforces_tls) {
    ii::Config cfg;
    cfg.default_mode = ii::Mode::Observe;
    cfg.by_group["telegram"] = ii::Mode::EnforceTls;
    Running run(std::make_unique<httplib::Server>(), [&cfg](httplib::Server& s) { routes(s, cfg); });

    nettls::Config plain;
    CHECK_EQ(status_of(plain, run.port(), "/internal/telegram/token"), 403);
    CHECK_EQ(status_of(plain, run.port(), "/internal/token/exchange", "wallet-ai"), 200);
}

TEST(ii_off_mode_changes_nothing) {
    ii::Config cfg; // off
    Running run(std::make_unique<httplib::Server>(), [&cfg](httplib::Server& s) { routes(s, cfg); });
    nettls::Config plain;
    CHECK_EQ(status_of(plain, run.port(), "/internal/telegram/token"), 200);
}
