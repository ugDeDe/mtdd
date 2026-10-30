#include "../support/control_fixture.hpp"

namespace {

constexpr const char* kReadToken = "unit-test-read-token-not-a-secret";

HttpOptions views_options() {
  HttpOptions options;
  options.read_token = kReadToken;
  options.config_json = R"({"proxy_port":443,"ad_tag_set":true})";
  options.system_info_json = R"({"workers_configured":2,"security":{"masking":true}})";
  return options;
}

TEST(ApiEnvelopeTest, EveryJsonReplyCarriesOkAndRequestId) {
  Harness h;
  const auto ok = h.req("GET", "/v1/health");
  ASSERT_EQ(ok.status, 200);
  const auto body = parse_json(ok);
  EXPECT_EQ(body["ok"], true);
  ASSERT_TRUE(body["request_id"].is_number_unsigned());
  EXPECT_EQ(header_value(ok, "X-Request-Id"),
            std::to_string(body["request_id"].get<uint64_t>()));
  EXPECT_EQ(body["data"]["status"], "ok");

  const auto missing = h.req("GET", "/v1/users/ghost");
  const auto error = parse_json(missing);
  EXPECT_EQ(error["ok"], false);
  EXPECT_GT(error["request_id"].get<uint64_t>(), body["request_id"].get<uint64_t>());
  EXPECT_EQ(error["error"]["type"], "not_found");

  const auto unauthorized = h.req("GET", "/v1/health", {}, "wrong-token");
  EXPECT_EQ(parse_json(unauthorized)["ok"], false);
}

TEST(ApiViewsTest, SystemInfoAndConfigAreReadableWithoutSecrets) {
  Harness h(StoreOptions{}, views_options());
  const auto info = h.req("GET", "/v1/system/info", {}, kReadToken);
  ASSERT_EQ(info.status, 200) << info.body;
  const auto data = parse_json(info)["data"];
  EXPECT_EQ(data["workers_configured"], 2);
  EXPECT_EQ(data["security"]["masking"], true);
  EXPECT_TRUE(data.contains("version"));
  EXPECT_TRUE(data["started_at"].get<std::string>().ends_with("Z"));
  EXPECT_GT(data["pid"].get<int64_t>(), 0);

  const auto config = h.req("GET", "/v1/config", {}, kReadToken);
  ASSERT_EQ(config.status, 200);
  EXPECT_EQ(parse_json(config)["data"]["config"]["proxy_port"], 443);
  EXPECT_EQ(config.body.find(kToken), std::string::npos);
  EXPECT_EQ(config.body.find(kReadToken), std::string::npos);

  HttpOptions bad;
  bad.config_json = "[1]";
  UserStore store = open_store_or_throw(h.dir().file("other.json"));
  Statistics stats;
  bad.bearer_token = kToken;
  ControlServer server(store, stats, bad);
  EXPECT_FALSE(server.start().ok());
}

TEST(ApiStatsTest, SummaryMeAndUsersStats) {
  Harness h(StoreOptions{}, views_options());
  for (const char* name : {"alice", "bob", "carol"}) {
    ASSERT_EQ(h.req("POST", "/v1/users", make_user_body(name)).status, 201);
  }
  h.stats().user("bob")->add_payload(mtdd::control::Direction::client_to_server, 500);
  h.stats().user("carol")->add_payload(mtdd::control::Direction::server_to_client, 900);
  h.stats().user("alice")->connection_opened();

  const auto summary = h.req("GET", "/v1/stats/summary", {}, kReadToken);
  ASSERT_EQ(summary.status, 200);
  const auto s = parse_json(summary)["data"];
  EXPECT_EQ(s["users"]["total"], 3);
  EXPECT_EQ(s["traffic"]["payload_bytes_total"], 1400);
  EXPECT_TRUE(s["unique_ips"]["online"].contains("active"));
  EXPECT_TRUE(s["unique_ips"]["week"].contains("seen"));

  const auto me = h.req("GET", "/v1/stats/me", {}, kReadToken);
  ASSERT_EQ(me.status, 200);
  EXPECT_TRUE(parse_json(me)["data"]["dcs"].is_array());

  const auto by_traffic = parse_json(h.req("GET", "/v1/stats/users?limit=2", {}, kReadToken));
  ASSERT_EQ(by_traffic["data"]["users"].size(), 2u);
  EXPECT_EQ(by_traffic["data"]["users"][0]["name"], "carol");
  EXPECT_EQ(by_traffic["data"]["users"][1]["name"], "bob");
  EXPECT_EQ(by_traffic["data"]["total"], 3);

  const auto by_conn =
      parse_json(h.req("GET", "/v1/stats/users?sort=connections", {}, kReadToken));
  EXPECT_EQ(by_conn["data"]["users"][0]["name"], "alice");
  const auto by_name =
      parse_json(h.req("GET", "/v1/stats/users?sort=name&offset=2", {}, kReadToken));
  ASSERT_EQ(by_name["data"]["users"].size(), 1u);
  EXPECT_EQ(by_name["data"]["users"][0]["name"], "carol");
  EXPECT_EQ(by_name.dump().find(std::string(kHexA)), std::string::npos);

  for (const char* bad : {"/v1/stats/users?sort=secret", "/v1/stats/users?limit=0",
                          "/v1/stats/users?limit=1001", "/v1/stats/users?limit=-1",
                          "/v1/stats/users?offset=x", "/v1/stats/users?bogus=1",
                          "/v1/stats/users?limit=1&limit=2",
                          // Decoded key is invalid UTF-8 and is echoed in the error.
                          "/v1/stats/users?%FF=1"}) {
    const auto response = h.req("GET", bad, {}, kReadToken);
    EXPECT_EQ(response.status, 400) << bad;
    EXPECT_EQ(parse_json(response)["error"]["type"], "invalid_query") << bad;
  }
}

TEST(ApiUsersTest, ListPaginatesAndFilters) {
  Harness h;
  for (const char* name : {"a1", "a2", "a3", "a4"}) {
    ASSERT_EQ(h.req("POST", "/v1/users", make_user_body(name)).status, 201);
  }
  ASSERT_EQ(h.req("POST", "/v1/users/a2/disable").status, 200);

  auto all = parse_json(h.req("GET", "/v1/users"))["data"];
  EXPECT_EQ(all["users"].size(), 4u);
  EXPECT_EQ(all["total"], 4);
  EXPECT_TRUE(all["limit"].is_null());

  auto page = parse_json(h.req("GET", "/v1/users?limit=2&offset=1"))["data"];
  ASSERT_EQ(page["users"].size(), 2u);
  EXPECT_EQ(page["users"][0]["name"], "a2");
  EXPECT_EQ(page["limit"], 2);

  auto enabled = parse_json(h.req("GET", "/v1/users?enabled=true"))["data"];
  EXPECT_EQ(enabled["total"], 3);
  auto disabled = parse_json(h.req("GET", "/v1/users?enabled=false"))["data"];
  ASSERT_EQ(disabled["users"].size(), 1u);
  EXPECT_EQ(disabled["users"][0]["name"], "a2");

  EXPECT_EQ(h.req("GET", "/v1/users?enabled=yes").status, 400);
  EXPECT_EQ(h.req("GET", "/v1/users?limit=10001").status, 400);
}

TEST(ApiUsersTest, EnableDisableActionsAndScopes) {
  Harness h(StoreOptions{}, views_options());
  ASSERT_EQ(h.req("POST", "/v1/users", make_user_body("alice")).status, 201);

  const auto off = h.req("POST", "/v1/users/alice/disable");
  ASSERT_EQ(off.status, 200) << off.body;
  EXPECT_EQ(parse_json(off)["data"]["user"]["enabled"], false);
  const uint64_t revision = parse_json(off)["data"]["revision"];

  const auto again = h.req("POST", "/v1/users/alice/disable", "{}");
  ASSERT_EQ(again.status, 200);
  EXPECT_EQ(parse_json(again)["data"]["revision"], revision);  // no-op

  const auto on = h.req("POST", "/v1/users/alice/enable", {}, kToken,
                        {{"If-Match", "\"" + std::to_string(revision) + "\""}});
  ASSERT_EQ(on.status, 200);
  EXPECT_EQ(parse_json(on)["data"]["user"]["enabled"], true);

  EXPECT_EQ(h.req("POST", "/v1/users/alice/enable", R"({"enabled":false})").status, 400);
  EXPECT_EQ(h.req("POST", "/v1/users/ghost/enable").status, 404);
  EXPECT_EQ(h.req("GET", "/v1/users/alice/enable").status, 405);
  EXPECT_EQ(h.req("POST", "/v1/users/alice/disable", {}, kReadToken).status, 403);
  EXPECT_EQ(h.req("POST", "/v1/users/alice/unknown-action").status, 404);
  EXPECT_EQ(h.req("POST", "/v1/users/alice/enable/x").status, 404);
}

TEST(ApiUsersTest, ResetQuotaZeroesUsageWithoutAdvancingRevision) {
  Harness h(StoreOptions{}, views_options());
  ASSERT_EQ(h.req("POST", "/v1/users",
                  R"({"name":"alice","data_quota_bytes":1048576})").status, 201);
  h.stats().user("alice")->add_payload(mtdd::control::Direction::server_to_client, 4096);

  auto shown = parse_json(h.req("GET", "/v1/users/alice"))["data"]["user"];
  EXPECT_EQ(shown["stats"]["quota_used_bytes"], 4096);
  EXPECT_TRUE(shown["stats"]["quota_reset_at"].is_null());
  const uint64_t revision = parse_json(h.req("GET", "/v1/users/alice"))["data"]["revision"];

  const auto row = parse_json(h.req("GET", "/v1/stats/users", {}, kReadToken));
  EXPECT_EQ(row["data"]["users"][0]["quota_used_bytes"], 4096);
  EXPECT_EQ(row["data"]["users"][0]["data_quota_bytes"], 1048576);

  EXPECT_EQ(h.req("POST", "/v1/users/alice/reset-quota", {}, kReadToken).status, 403);
  EXPECT_EQ(h.req("POST", "/v1/users/alice/reset-quota", R"({"x":1})").status, 400);
  EXPECT_EQ(h.req("POST", "/v1/users/alice/reset-quota", {}, kToken,
                  {{"If-Match", "\"" + std::to_string(revision + 1) + "\""}}).status,
            412);
  EXPECT_EQ(h.req("POST", "/v1/users/ghost/reset-quota").status, 404);
  EXPECT_EQ(h.stats().user("alice")->quota_used_bytes(), 4096u);  // failures change nothing

  const auto reset = h.req("POST", "/v1/users/alice/reset-quota", {}, kToken,
                           {{"If-Match", "\"" + std::to_string(revision) + "\""}});
  ASSERT_EQ(reset.status, 200) << reset.body;
  const auto data = parse_json(reset)["data"];
  EXPECT_EQ(data["revision"], revision);
  EXPECT_EQ(data["user"]["stats"]["quota_used_bytes"], 0);
  EXPECT_TRUE(data["user"]["stats"]["quota_reset_at"].get<std::string>().ends_with("Z"));
  EXPECT_EQ(h.stats().user("alice")->quota_used_bytes(), 0u);

  const auto events = parse_json(h.req("GET", "/v1/events", {}, kReadToken))["data"]["events"];
  ASSERT_EQ(events.size(), 2u);
  EXPECT_EQ(events[1]["action"], "user.reset_quota");
  EXPECT_EQ(events[1]["revision"], revision);
}

TEST(ApiEventsTest, AuditRingRecordsMutationsWithoutSecrets) {
  Harness h(StoreOptions{}, views_options());
  ASSERT_EQ(h.req("POST", "/v1/users",
                  make_user_body("alice", std::string(kHexA))).status, 201);
  ASSERT_EQ(h.req("PATCH", "/v1/users/alice", R"({"note":"vip","enabled":false})").status, 200);
  ASSERT_EQ(h.req("POST", "/v1/users/alice/rotate-secret", "{}").status, 200);
  ASSERT_EQ(h.req("POST", "/v1/users/alice/enable").status, 200);
  ASSERT_EQ(h.req("DELETE", "/v1/users/alice").status, 200);
  ASSERT_EQ(h.req("PATCH", "/v1/users/ghost", R"({"enabled":true})").status, 404);

  const auto listing = h.req("GET", "/v1/events", {}, kReadToken);
  ASSERT_EQ(listing.status, 200);
  const auto events = parse_json(listing)["data"]["events"];
  ASSERT_EQ(events.size(), 5u);  // failed mutations are not recorded
  const std::vector<std::string> actions = {"user.create", "user.update",
                                            "user.rotate_secret", "user.enable",
                                            "user.delete"};
  for (size_t i = 0; i < actions.size(); ++i) {
    EXPECT_EQ(events[i]["action"], actions[i]);
    EXPECT_EQ(events[i]["user"], "alice");
    EXPECT_EQ(events[i]["id"], i + 1);
    EXPECT_EQ(events[i]["source"], "127.0.0.1");
  }
  EXPECT_EQ(events[1]["fields"], nlohmann::json({"enabled", "note"}));
  EXPECT_EQ(listing.body.find(kHexA), std::string::npos);

  const auto page = parse_json(h.req("GET", "/v1/events?after=3&limit=1", {}, kReadToken));
  ASSERT_EQ(page["data"]["events"].size(), 1u);
  EXPECT_EQ(page["data"]["events"][0]["id"], 4);
  EXPECT_EQ(page["data"]["next_after"], 4);
  EXPECT_EQ(h.req("GET", "/v1/events?limit=257").status, 400);
}

TEST(ApiEventsTest, RingKeepsOnlyTheNewest256) {
  HttpOptions options;
  options.rate_limit_per_second = 10000.0;
  options.rate_limit_burst = 10000.0;
  options.global_rate_limit_per_second = 10000.0;
  options.global_rate_limit_burst = 10000.0;
  Harness h(StoreOptions{}, options);
  ASSERT_EQ(h.req("POST", "/v1/users", make_user_body("alice")).status, 201);
  for (int i = 0; i < 300; ++i) {
    ASSERT_EQ(h.req("POST", i % 2 ? "/v1/users/alice/enable" : "/v1/users/alice/disable")
                  .status,
              200);
  }
  const auto listing = h.req("GET", "/v1/events?limit=256");
  ASSERT_EQ(listing.status, 200) << listing.error;
  ASSERT_TRUE(listing.error.empty()) << listing.error;
  const auto data = parse_json(listing)["data"];
  EXPECT_EQ(data["events"].size(), 256u);
  EXPECT_EQ(data["oldest_id"], 301 - 255);
  EXPECT_EQ(data["events"].back()["id"], 301);
}

}  // namespace
