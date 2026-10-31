#include "../support/control_fixture.hpp"

#include "../../src/control/http_internal.hpp"

namespace {

using mtdd::control::UserPolicy;
using mtdd::control::UserPolicyPatch;
using mtdd::control::SuspectSignal;

UserPolicy full_policy() {
  UserPolicy policy;
  policy.expires_at = 1893456000;  // 2030-01-01
  policy.data_quota_bytes = 10ull << 30;
  policy.max_unique_ips = 3;
  policy.max_devices = 2;
  policy.canary = true;
  policy.rate_limit_up_bytes_per_sec = 1 << 20;
  policy.rate_limit_down_bytes_per_sec = 4 << 20;
  policy.note = "семья · laptop";
  return policy;
}

TEST(UserPolicyStoreTest, PolicyPersistsAsVersionTwoAndRoundTrips) {
  TempDir dir;
  const auto path = dir.file("users.json");
  {
    auto store = open_store_or_throw(path);
    CreateUserRequest plain;
    plain.name = "plain";
    ASSERT_TRUE(store.create_user(plain).ok());
    EXPECT_EQ(nlohmann::json::parse(read_text_file(path))["version"], 1);

    CreateUserRequest request;
    request.name = "alice";
    request.policy = full_policy();
    auto created = store.create_user(request);
    ASSERT_TRUE(created.ok()) << created.error().message;
    EXPECT_EQ(created.value().user.policy, full_policy());
  }
  const auto file = nlohmann::json::parse(read_text_file(path));
  EXPECT_EQ(file["version"], 2);
  EXPECT_TRUE(file["users"][1]["data_quota_bytes"].is_null());  // "plain"

  auto reopened = open_store_or_throw(path);
  const auto snapshot = reopened.snapshot();
  ASSERT_EQ(snapshot->users.size(), 2u);
  EXPECT_EQ(snapshot->users[0].name, "alice");
  EXPECT_EQ(snapshot->users[0].policy, full_policy());
  EXPECT_TRUE(snapshot->users[1].policy.empty());
}

TEST(UserPolicyStoreTest, PatchSetsClearsAndSkipsNoOps) {
  TempDir dir;
  const auto path = dir.file("users.json");
  auto store = open_store_or_throw(path);
  CreateUserRequest create;
  create.name = "alice";
  ASSERT_TRUE(store.create_user(create).ok());

  UpdateUserRequest set;
  set.name = "alice";
  set.policy.data_quota_bytes = std::optional<uint64_t>(1024);
  set.policy.note = std::string("vip");
  auto updated = store.update_user(set);
  ASSERT_TRUE(updated.ok()) << updated.error().message;
  const uint64_t revision = updated.value().revision;
  EXPECT_EQ(updated.value().user.policy.data_quota_bytes, 1024u);
  EXPECT_FALSE(updated.value().user.policy.expires_at);

  auto again = store.update_user(set);
  ASSERT_TRUE(again.ok());
  EXPECT_EQ(again.value().revision, revision);

  UpdateUserRequest clear;
  clear.name = "alice";
  clear.policy.data_quota_bytes = std::optional<uint64_t>{};
  clear.policy.note = std::string();
  auto cleared = store.update_user(clear);
  ASSERT_TRUE(cleared.ok());
  EXPECT_TRUE(cleared.value().user.policy.empty());
  EXPECT_EQ(nlohmann::json::parse(read_text_file(path))["version"], 1);
}

TEST(UserPolicyStoreTest, RejectsOutOfRangeValuesWithoutMutating) {
  TempDir dir;
  auto store = open_store_or_throw(dir.file("users.json"));
  CreateUserRequest create;
  create.name = "alice";
  ASSERT_TRUE(store.create_user(create).ok());
  const uint64_t revision = store.snapshot()->revision;

  const auto rejects = [&](auto mutate) {
    UpdateUserRequest request;
    request.name = "alice";
    mutate(request.policy);
    auto result = store.update_user(request);
    ASSERT_FALSE(result.ok());
    EXPECT_EQ(result.error().code, ErrorCode::invalid_field);
  };
  rejects([](UserPolicyPatch& p) { p.data_quota_bytes = std::optional<uint64_t>(0); });
  rejects([](UserPolicyPatch& p) { p.max_unique_ips = std::optional<uint32_t>(0); });
  rejects([](UserPolicyPatch& p) { p.max_devices = std::optional<uint32_t>(0); });
  rejects([](UserPolicyPatch& p) { p.rate_limit_up_bytes_per_sec = std::optional<uint64_t>(1023); });
  rejects([](UserPolicyPatch& p) { p.expires_at = std::optional<int64_t>(-1); });
  rejects([](UserPolicyPatch& p) { p.note = std::string(257, 'x'); });
  rejects([](UserPolicyPatch& p) { p.note = std::string("line\nbreak"); });
  rejects([](UserPolicyPatch& p) { p.note = std::string("\x1b[2J"); });
  rejects([](UserPolicyPatch& p) { p.note = std::string("\xc3"); });          // truncated
  rejects([](UserPolicyPatch& p) { p.note = std::string("\xc0\xaf"); });      // overlong
  rejects([](UserPolicyPatch& p) { p.note = std::string("\xed\xa0\x80"); });  // surrogate
  rejects([](UserPolicyPatch& p) { p.note = std::string("\xc2\x9b"); });      // C1 CSI
  EXPECT_EQ(store.snapshot()->revision, revision);

  UpdateUserRequest empty;
  empty.name = "alice";
  auto result = store.update_user(empty);
  ASSERT_FALSE(result.ok());
  EXPECT_EQ(result.error().code, ErrorCode::invalid_request);
}

TEST(UserPolicyStoreTest, FileVersionGatesPolicyFields) {
  TempDir dir;
  const std::string user =
      R"({"name":"alice","secret":"00112233445566778899aabbccddeeff","enabled":true,)"
      R"("max_connections":null,"generation":1,"data_quota_bytes":100})";
  write_text_file(dir.file("v1.json"),
                  R"({"version":1,"revision":1,"users":[)" + user + "]}");
  auto v1 = UserStore::open(dir.file("v1.json"));
  ASSERT_FALSE(v1.ok());
  EXPECT_EQ(v1.error().code, ErrorCode::unknown_field);

  write_text_file(dir.file("v2.json"),
                  R"({"version":2,"revision":1,"users":[)" + user + "]}");
  auto v2 = UserStore::open(dir.file("v2.json"));
  ASSERT_TRUE(v2.ok()) << v2.error().message;
  EXPECT_EQ(v2.value().snapshot()->users[0].policy.data_quota_bytes, 100u);

  write_text_file(dir.file("bad.json"),
                  R"({"version":2,"revision":1,"users":[{"name":"alice",)"
                  R"("secret":"00112233445566778899aabbccddeeff","enabled":true,)"
                  R"("generation":1,"note":"\u0007"}]})");
  auto bad = UserStore::open(dir.file("bad.json"));
  ASSERT_FALSE(bad.ok());
  EXPECT_EQ(bad.error().code, ErrorCode::invalid_field);
}

TEST(UserPolicyHttpTest, CreatePatchAndReadPolicyFields) {
  Harness h;
  const auto created = h.req(
      "POST", "/v1/users",
      R"({"name":"alice","expires_at":"2030-01-01T03:00:00+03:00",)"
      R"("data_quota_bytes":1073741824,"max_unique_ips":2,)"
      R"("rate_limit_down_bytes_per_sec":1048576,"max_devices":3,"note":"vip"})");
  ASSERT_EQ(created.status, 201) << created.body;
  auto user = parse_json(created)["data"]["user"];
  EXPECT_EQ(user["expires_at"], "2030-01-01T00:00:00Z");
  EXPECT_EQ(user["data_quota_bytes"], 1073741824u);
  EXPECT_EQ(user["max_unique_ips"], 2);
  EXPECT_EQ(user["max_devices"], 3);
  EXPECT_TRUE(user["rate_limit_up_bytes_per_sec"].is_null());
  EXPECT_EQ(user["note"], "vip");

  const auto patched = h.req("PATCH", "/v1/users/alice",
                             R"({"expires_at":null,"note":"","max_unique_ips":null,)"
                             R"("max_devices":null})");
  ASSERT_EQ(patched.status, 200) << patched.body;
  user = parse_json(patched)["data"]["user"];
  EXPECT_TRUE(user["expires_at"].is_null());
  EXPECT_TRUE(user["max_unique_ips"].is_null());
  EXPECT_TRUE(user["max_devices"].is_null());
  EXPECT_EQ(user["data_quota_bytes"], 1073741824u);
  EXPECT_EQ(user["note"], "");

  const auto plain = h.req("POST", "/v1/users", make_user_body("bob"));
  ASSERT_EQ(plain.status, 201);
  EXPECT_TRUE(parse_json(plain)["data"]["user"]["expires_at"].is_null());
}

TEST(UserPolicyHttpTest, RejectsMalformedPolicyFields) {
  Harness h;
  ASSERT_EQ(h.req("POST", "/v1/users", make_user_body("alice")).status, 201);
  for (const char* body :
       {R"({"expires_at":1893456000})", R"({"expires_at":"2030-02-30T00:00:00Z"})",
        R"({"expires_at":"2030-01-01 00:00:00Z"})", R"({"expires_at":"2030-01-01T00:00:00"})",
        R"({"data_quota_bytes":-1})", R"({"data_quota_bytes":0})", R"({"data_quota_bytes":1.5})",
        R"({"max_unique_ips":"3"})", R"({"max_unique_ips":4294967296})",
        R"({"max_devices":0})", R"({"max_devices":1000001})",
        R"({"rate_limit_up_bytes_per_sec":100})", R"({"note":5})", R"({"note":null})"}) {
    const auto response = h.req("PATCH", "/v1/users/alice", body);
    EXPECT_EQ(response.status, 400) << body << " -> " << response.body;
    EXPECT_EQ(parse_json(response)["error"]["type"], "invalid_field") << body;
  }
}

TEST(Rfc3339Test, ParsesAndFormatsUtc) {
  using mtdd::control::detail::format_rfc3339;
  using mtdd::control::detail::parse_rfc3339;
  EXPECT_EQ(parse_rfc3339("1970-01-01T00:00:00Z"), 0);
  EXPECT_EQ(parse_rfc3339("2024-02-29T12:34:56.789z"), 1709210096);
  EXPECT_EQ(parse_rfc3339("2030-01-01T00:00:00-01:30"), 1893461400);
  EXPECT_FALSE(parse_rfc3339("2023-02-29T00:00:00Z"));
  EXPECT_FALSE(parse_rfc3339("2030-01-01T24:00:00Z"));
  EXPECT_FALSE(parse_rfc3339("2030-01-01T00:00:00.Z"));
  EXPECT_FALSE(parse_rfc3339("2030-01-01T00:00:00+0100"));
  EXPECT_EQ(format_rfc3339(0), "1970-01-01T00:00:00Z");
  EXPECT_EQ(format_rfc3339(1709210096), "2024-02-29T12:34:56Z");
  EXPECT_EQ(format_rfc3339(253402300799), "9999-12-31T23:59:59Z");
}

}  // namespace

TEST(UserPolicyHttpTest, DevicesRouteListsConnectedFirst) {
  Harness h;
  ASSERT_EQ(h.req("POST", "/v1/users", make_user_body("alice")).status, 201);
  EXPECT_EQ(h.req("GET", "/v1/users/nobody/devices").status, 404);
  auto empty = h.req("GET", "/v1/users/alice/devices");
  ASSERT_EQ(empty.status, 200) << empty.body;
  EXPECT_TRUE(parse_json(empty)["data"]["keys"].empty());

  h.stats().set_device_lister([](const std::string& user) {
    std::vector<Statistics::DeviceInfo> out;
    if (user != "alice") return out;
    out.push_back({0x1a2b3c4d, 2, 0, 120, "10.0.0.1"});
    out.push_back({0x0000beef, -2, 3, 0, "10.0.0.2"});
    return out;
  });
  h.stats().user("alice")->set_devices(2, 1);
  const auto listed = h.req("GET", "/v1/users/alice/devices");
  ASSERT_EQ(listed.status, 200) << listed.body;
  const auto data = parse_json(listed)["data"];
  EXPECT_EQ(data["devices_connected"], 1);
  EXPECT_EQ(data["devices"], 2);
  ASSERT_EQ(data["keys"].size(), 2u);
  EXPECT_EQ(data["keys"][0]["id"], "0000beef");
  EXPECT_EQ(data["keys"][0]["connected"], true);
  EXPECT_EQ(data["keys"][0]["dc"], -2);
  EXPECT_EQ(data["keys"][1]["idle_seconds"], 120);
  EXPECT_EQ(data["keys"][1]["ip"], "10.0.0.1");
  EXPECT_EQ(h.req("POST", "/v1/users/alice/devices").status, 405);
  h.stats().set_device_lister({});
}

TEST(UserPolicyHttpTest, CanaryFlagIsABoolean) {
  Harness h;
  const auto created = h.req("POST", "/v1/users", R"({"name":"bait","canary":true})");
  ASSERT_EQ(created.status, 201) << created.body;
  EXPECT_EQ(parse_json(created)["data"]["user"]["canary"], true);
  EXPECT_EQ(h.req("PATCH", "/v1/users/bait", R"({"canary":"yes"})").status, 400);
  const auto cleared = h.req("PATCH", "/v1/users/bait", R"({"canary":false})");
  ASSERT_EQ(cleared.status, 200) << cleared.body;
  EXPECT_EQ(parse_json(cleared)["data"]["user"]["canary"], false);
}

TEST(SuspectsHttpTest, SortsByMatchesFiltersAndExportsIps) {
  Harness h;
  auto empty = h.req("GET", "/v1/suspects");
  ASSERT_EQ(empty.status, 200) << empty.body;
  EXPECT_TRUE(parse_json(empty)["data"]["suspects"].empty());

  h.stats().set_suspect_lister([] {
    std::vector<Statistics::SuspectInfo> rows(3);
    rows[0].ip = "198.51.100.1";  // one signal, high score
    rows[0].hits[static_cast<size_t>(SuspectSignal::canary)] = 5;
    rows[0].matches = 1;
    rows[0].score = 100;
    rows[0].last_seen = 1893456000;
    rows[1].ip = "203.0.113.9";  // three signals, lower score
    rows[1].hits[static_cast<size_t>(SuspectSignal::probe_session)] = 2;
    rows[1].hits[static_cast<size_t>(SuspectSignal::raw_obfuscated2)] = 2;
    rows[1].hits[static_cast<size_t>(SuspectSignal::multi_mode)] = 1;
    rows[1].matches = 3;
    rows[1].score = 85.4;
    rows[1].user = "dd";
    rows[1].platform = "Linux";
    rows[1].shadow_banned = true;
    rows[2].ip = "192.0.2.4";
    rows[2].hits[static_cast<size_t>(SuspectSignal::junk)] = 1;
    rows[2].matches = 1;
    rows[2].score = 5;
    return rows;
  });
  const auto listed = h.req("GET", "/v1/suspects");
  ASSERT_EQ(listed.status, 200) << listed.body;
  const auto data = parse_json(listed)["data"];
  EXPECT_EQ(data["total"], 3);
  EXPECT_EQ(data["by_matches"]["1"], 2);
  EXPECT_EQ(data["by_matches"]["3"], 1);
  EXPECT_EQ(data["shadow_banned"], 1);
  ASSERT_EQ(data["suspects"].size(), 3u);
  EXPECT_EQ(data["suspects"][0]["ip"], "203.0.113.9");  // most matches first
  EXPECT_EQ(data["suspects"][0]["signals"]["probe_session"], 2);
  EXPECT_EQ(data["suspects"][0]["hits"], 5);
  EXPECT_EQ(data["suspects"][0]["user"], "dd");
  EXPECT_EQ(data["suspects"][1]["ip"], "198.51.100.1");
  EXPECT_TRUE(data["suspects"][2]["user"].is_null());

  const auto by_score = parse_json(h.req("GET", "/v1/suspects?sort=score"))["data"];
  EXPECT_EQ(by_score["suspects"][0]["ip"], "198.51.100.1");
  const auto filtered = parse_json(h.req("GET", "/v1/suspects?min_matches=2"))["data"];
  EXPECT_EQ(filtered["filtered"], 1);
  const auto ips = h.req("GET", "/v1/suspects?format=ips&min_score=50");
  ASSERT_EQ(ips.status, 200);
  EXPECT_EQ(ips.body, "203.0.113.9\n198.51.100.1\n");
  EXPECT_EQ(h.req("GET", "/v1/suspects?sort=bogus").status, 400);
  EXPECT_EQ(h.req("GET", "/v1/suspects?min_matches=10").status, 400);
  EXPECT_EQ(h.req("POST", "/v1/suspects").status, 405);
  EXPECT_NE(h.req("GET", "/metrics").body.find("mtdd_suspects{matches=\"3\"} 1"), std::string::npos);
  h.stats().set_suspect_lister({});
}
