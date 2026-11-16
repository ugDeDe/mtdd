// GET/PATCH/DELETE /v1/shaping: request shape, scopes, audit and hook wiring.
// The rules themselves are parsed by the leader (parse_shaping); here a fake
// hook stands in for it.
#include "../support/control_fixture.hpp"

#include <mutex>

namespace {

constexpr const char* kShapingReadToken = "unit-test-read-token-not-a-secret";

// Records every update and serves a view that reflects the last one.
struct FakeShaping {
  std::mutex mutex;
  std::vector<std::optional<std::string>> updates;
  std::string reject_with;  // non-empty: the next updates fail with it
  bool overridden{false};
  nlohmann::json effective = {{"media_download", {{"user_kbps", 0}}},
                              {"media_upload", {{"user_kbps", 0}}}};

  void install(HttpOptions& options) {
    options.shaping_view_hook = [this] {
      std::lock_guard lock{mutex};
      return nlohmann::json{
          {"source", overridden ? "api" : "config"},
          {"effective", effective},
          {"configured", {{"media_download", {{"user_kbps", 0}}}}},
          {"state", {{"media_download", {{"active_users", 3}, {"heavy_users", 1},
                                         {"light_bytes_per_sec", 1000}}},
                     {"media_upload", {{"active_users", 0}, {"heavy_users", 0},
                                       {"light_bytes_per_sec", 0}}}}}}
          .dump();
    };
    options.shaping_update_hook = [this](const std::optional<std::string>& patch) {
      std::lock_guard lock{mutex};
      updates.push_back(patch);
      if (!reject_with.empty()) return reject_with;
      overridden = patch.has_value();
      if (patch) effective.merge_patch(nlohmann::json::parse(*patch));
      return std::string{};
    };
  }

  size_t update_count() {
    std::lock_guard lock{mutex};
    return updates.size();
  }
};

HttpOptions shaping_options() {
  HttpOptions options;
  options.read_token = kShapingReadToken;
  return options;
}

nlohmann::json shaping_events(Harness& h) {
  nlohmann::json out = nlohmann::json::array();
  const auto listing = parse_json(h.req("GET", "/v1/events"));
  for (const auto& event : listing["data"]["events"]) {
    const std::string action = event["action"];
    if (action.rfind("shaping.", 0) == 0) out.push_back(event);
  }
  return out;
}

}  // namespace

TEST(HttpShapingTest, GetServesTheHookViewToReadAndAdminTokens) {
  FakeShaping fake;
  HttpOptions options = shaping_options();
  fake.install(options);
  Harness h(StoreOptions{}, options);

  for (const char* token : {kToken, kShapingReadToken}) {
    const auto response = h.req("GET", "/v1/shaping", {}, token);
    ASSERT_EQ(response.status, 200) << response.body;
    const auto data = parse_json(response)["data"];
    EXPECT_EQ(data["source"], "config");
    EXPECT_EQ(data["effective"]["media_download"]["user_kbps"], 0);
    EXPECT_EQ(data["state"]["media_download"]["active_users"], 3);
    EXPECT_EQ(data["state"]["media_download"]["heavy_users"], 1);
    EXPECT_EQ(data["state"]["media_download"]["light_bytes_per_sec"], 1000);
  }
  EXPECT_EQ(fake.update_count(), 0u);
}

TEST(HttpShapingTest, PatchPassesTheBodyToTheHookAndAnswersWithTheView) {
  FakeShaping fake;
  HttpOptions options = shaping_options();
  fake.install(options);
  Harness h(StoreOptions{}, options);

  const auto response =
      h.req("PATCH", "/v1/shaping", R"({"media_download":{"user_kbps":8000,"burst_kib":4096}})");
  ASSERT_EQ(response.status, 200) << response.body;
  const auto data = parse_json(response)["data"];
  EXPECT_EQ(data["source"], "api");
  EXPECT_EQ(data["effective"]["media_download"]["user_kbps"], 8000);
  EXPECT_EQ(data["effective"]["media_download"]["burst_kib"], 4096);
  ASSERT_EQ(fake.update_count(), 1u);
  ASSERT_TRUE(fake.updates[0].has_value());
  EXPECT_EQ(nlohmann::json::parse(*fake.updates[0]),
            nlohmann::json::parse(R"({"media_download":{"user_kbps":8000,"burst_kib":4096}})"));
  EXPECT_EQ(parse_json(h.req("GET", "/v1/shaping"))["data"]["source"], "api");

  const auto events = shaping_events(h);
  ASSERT_EQ(events.size(), 1u);
  EXPECT_EQ(events[0]["action"], "shaping.override");
  EXPECT_EQ(events[0]["fields"],
            nlohmann::json::parse(R"(["media_download.burst_kib","media_download.user_kbps"])"));
  // Only names reach the audit log, never the values.
  EXPECT_EQ(h.req("GET", "/v1/events").body.find("8000"), std::string::npos);
}

TEST(HttpShapingTest, PatchRejectsEmptyOrMalformedBodiesBeforeTheHook) {
  FakeShaping fake;
  HttpOptions options = shaping_options();
  fake.install(options);
  Harness h(StoreOptions{}, options);

  for (const char* bad : {"{}", "", "[]", "not json", R"("media_download")"}) {
    const auto response = h.req("PATCH", "/v1/shaping", bad);
    EXPECT_EQ(response.status, 400) << bad;
  }
  EXPECT_EQ(parse_json(h.req("PATCH", "/v1/shaping", "{}"))["error"]["type"], "invalid_field");
  EXPECT_EQ(fake.update_count(), 0u);
  EXPECT_TRUE(shaping_events(h).empty());
}

TEST(HttpShapingTest, HookValidationErrorIsA400WithItsMessage) {
  FakeShaping fake;
  fake.reject_with = "unknown configuration option: shaping.media_download.rate";
  HttpOptions options = shaping_options();
  fake.install(options);
  Harness h(StoreOptions{}, options);

  const auto response = h.req("PATCH", "/v1/shaping", R"({"media_download":{"rate":1}})");
  ASSERT_EQ(response.status, 400);
  const auto error = parse_json(response)["error"];
  EXPECT_EQ(error["type"], "invalid_field");
  EXPECT_EQ(error["message"], fake.reject_with);
  EXPECT_EQ(fake.update_count(), 1u);
  EXPECT_EQ(parse_json(h.req("GET", "/v1/shaping"))["data"]["source"], "config");
  EXPECT_TRUE(shaping_events(h).empty());  // failed changes are not recorded
}

TEST(HttpShapingTest, DeleteDropsTheOverrideAndIsAudited) {
  FakeShaping fake;
  HttpOptions options = shaping_options();
  fake.install(options);
  Harness h(StoreOptions{}, options);

  ASSERT_EQ(h.req("PATCH", "/v1/shaping", R"({"media_upload":{"total_kbps":1000}})").status, 200);
  const auto response = h.req("DELETE", "/v1/shaping");
  ASSERT_EQ(response.status, 200) << response.body;
  EXPECT_EQ(parse_json(response)["data"]["source"], "config");
  ASSERT_EQ(fake.update_count(), 2u);
  EXPECT_FALSE(fake.updates[1].has_value());

  const auto events = shaping_events(h);
  ASSERT_EQ(events.size(), 2u);
  EXPECT_EQ(events[0]["action"], "shaping.override");
  EXPECT_EQ(events[1]["action"], "shaping.reset");
  EXPECT_EQ(events[1]["fields"], nlohmann::json::parse(R"(["shaping"])"));
}

TEST(HttpShapingTest, ReadTokenCannotChangeShaping) {
  FakeShaping fake;
  HttpOptions options = shaping_options();
  fake.install(options);
  Harness h(StoreOptions{}, options);

  EXPECT_EQ(h.req("PATCH", "/v1/shaping", R"({"media_download":{"user_kbps":1}})",
                  kShapingReadToken).status, 403);
  EXPECT_EQ(h.req("DELETE", "/v1/shaping", {}, kShapingReadToken).status, 403);
  EXPECT_EQ(fake.update_count(), 0u);
}

TEST(HttpShapingTest, UnsupportedMethodsAre405) {
  FakeShaping fake;
  HttpOptions options = shaping_options();
  fake.install(options);
  Harness h(StoreOptions{}, options);

  EXPECT_EQ(h.req("POST", "/v1/shaping", R"({"media_download":{"user_kbps":1}})").status, 405);
  EXPECT_EQ(h.req("PUT", "/v1/shaping", R"({"media_download":{"user_kbps":1}})").status, 405);
  EXPECT_EQ(fake.update_count(), 0u);
}

TEST(HttpShapingTest, RouteIs404WithoutHooks) {
  Harness plain(StoreOptions{}, shaping_options());
  EXPECT_EQ(plain.req("GET", "/v1/shaping").status, 404);
  EXPECT_EQ(plain.req("PATCH", "/v1/shaping", R"({"media_download":{"user_kbps":1}})").status, 404);
  EXPECT_EQ(plain.req("DELETE", "/v1/shaping").status, 404);

  // Half-wired is still unavailable.
  HttpOptions options = shaping_options();
  options.shaping_view_hook = [] { return std::string{"{}"}; };
  Harness half(StoreOptions{}, options);
  EXPECT_EQ(half.req("GET", "/v1/shaping").status, 404);
}
