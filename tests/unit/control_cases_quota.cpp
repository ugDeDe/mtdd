// Quota counter, rate-bucket arithmetic and the private usage-state file.
#include "../support/control_fixture.hpp"

#include <mtdd/usage_state.hpp>

namespace {

using mtdd::control::UsageMap;
using mtdd::control::UsageRecord;
using mtdd::control::UsageStateKeeper;

TEST(QuotaTest, CounterCountsBothDirectionsAndResets) {
  Statistics stats;
  auto alice = stats.user("alice");
  ASSERT_NE(alice, nullptr);
  EXPECT_EQ(alice->quota_used_bytes(), 0U);
  EXPECT_EQ(alice->quota_reset_at(), 0);

  alice->add_payload(Direction::client_to_server, 100);
  alice->add_payload(Direction::server_to_client, 250);
  EXPECT_EQ(alice->quota_used_bytes(), 350U);
  EXPECT_EQ(alice->payload_c2s_bytes(), 100U);
  EXPECT_EQ(alice->payload_s2c_bytes(), 250U);

  const auto before = std::chrono::duration_cast<std::chrono::seconds>(
                          std::chrono::system_clock::now().time_since_epoch())
                          .count();
  alice->reset_quota();
  EXPECT_EQ(alice->quota_used_bytes(), 0U);
  EXPECT_GE(alice->quota_reset_at(), before);
  EXPECT_LE(alice->quota_reset_at(), before + 5);
  // Lifetime payload totals are not touched by a quota reset.
  EXPECT_EQ(alice->payload_c2s_bytes(), 100U);

  alice->set_quota_used_bytes(777);
  EXPECT_EQ(alice->quota_used_bytes(), 777U);

  const auto snapshot = stats.snapshot();
  EXPECT_EQ(snapshot.users.at("alice").quota_used_bytes, 777U);
  EXPECT_EQ(snapshot.users.at("alice").quota_reset_at, alice->quota_reset_at());
}

TEST(QuotaTest, PrometheusExposesQuotaGaugeAndNewRejectReasons) {
  Statistics stats;
  stats.user("alice")->set_quota_used_bytes(4242);
  stats.connection_rejected(RejectReason::user_connection_limit);
  stats.connection_rejected(RejectReason::user_expired);
  stats.connection_rejected(RejectReason::user_quota_exceeded);
  stats.connection_rejected(RejectReason::user_ip_limit);
  const std::string text = stats.prometheus_text();
  EXPECT_NE(text.find("# HELP mtdd_user_quota_used_bytes"), std::string::npos);
  EXPECT_NE(text.find("# TYPE mtdd_user_quota_used_bytes gauge"), std::string::npos);
  EXPECT_NE(text.find("mtdd_user_quota_used_bytes{user=\"alice\"} 4242"), std::string::npos);
  for (const char* reason :
       {"user_connection_limit", "user_expired", "user_quota_exceeded", "user_ip_limit"}) {
    EXPECT_NE(text.find(std::string("reason=\"") + reason + "\""), std::string::npos) << reason;
  }
  const auto snapshot = stats.snapshot();
  EXPECT_EQ(snapshot.connections_rejected_total, 4U);
  EXPECT_EQ(snapshot.rejected_by_reason.at("user_ip_limit"), 1U);
}

TEST(QuotaTest, RateBucketAllowsBurstThenPacesAtRate) {
  Statistics stats;
  auto user = stats.user("alice");
  constexpr uint64_t kRate = 1000 * 1000;  // 1 MB/s, burst = max(rate, 64 KiB)
  EXPECT_EQ(mtdd::control::UserMetrics::rate_burst_bytes(10), 64U * 1024U);
  EXPECT_EQ(mtdd::control::UserMetrics::rate_burst_bytes(kRate), kRate);
  const int64_t t0 = 1'000'000'000'000;
  // Half a second of data is within the one second burst: no pause.
  EXPECT_EQ(user->rate_consume(Direction::client_to_server, kRate / 2, kRate, t0), 0);
  EXPECT_EQ(user->rate_consume(Direction::client_to_server, kRate / 2, kRate, t0), 0);
  // The next half second overdraws: resume once the debt is back at the burst.
  const int64_t resume = user->rate_consume(Direction::client_to_server, kRate / 2, kRate, t0);
  EXPECT_EQ(resume, t0 + 500'000'000);
  EXPECT_EQ(user->rate_resume_at(Direction::client_to_server, kRate, t0), resume);
  EXPECT_EQ(user->rate_resume_at(Direction::client_to_server, kRate, resume), 0);
  // Directions are independent buckets.
  EXPECT_EQ(user->rate_resume_at(Direction::server_to_client, kRate, t0), 0);
  // rate 0 means unlimited.
  EXPECT_EQ(user->rate_consume(Direction::client_to_server, 1 << 30, 0, t0), 0);
}

TEST(UsageStateTest, SerializeParseRoundTrip) {
  UsageMap usage;
  usage["alice"] = UsageRecord{123, 1700000000};
  usage["bob"] = UsageRecord{0, 0};
  const std::string text = mtdd::control::serialize_usage_state(usage);
  std::string error;
  const auto parsed = mtdd::control::parse_usage_state(text, &error);
  ASSERT_TRUE(parsed.has_value()) << error;
  EXPECT_EQ(*parsed, usage);
  EXPECT_NE(text.find("\"version\":1"), std::string::npos);
}

TEST(UsageStateTest, StrictParseRejectsMalformedInput) {
  const char* const bad[] = {
      "",
      "not json",
      "[]",
      R"({"users":{}})",                                   // missing version
      R"({"version":1})",                                  // missing users
      R"({"version":2,"users":{}})",                       // wrong version
      R"({"version":"1","users":{}})",                     // version type
      R"({"version":1,"users":[]})",                       // users type
      R"({"version":1,"users":{},"extra":1})",             // unknown top-level key
      R"({"version":1,"users":{"a":{"used":1}}})",         // missing reset_at
      R"({"version":1,"users":{"a":{"used":-1,"reset_at":0}}})",   // negative
      R"({"version":1,"users":{"a":{"used":1.5,"reset_at":0}}})",  // not integer
      R"({"version":1,"users":{"a":{"used":"1","reset_at":0}}})",  // string
      R"({"version":1,"users":{"a":{"used":1,"reset_at":-5}}})",   // negative time
      R"({"version":1,"users":{"a":{"used":1,"reset_at":0,"x":1}}})",  // unknown key
      R"({"version":1,"users":{"a b":{"used":1,"reset_at":0}}})",  // invalid name
      R"({"version":1,"users":{"":{"used":1,"reset_at":0}}})",     // empty name
      R"({"version":1,"users":{"a":{"used":18446744073709551616,"reset_at":0}}})",  // overflow
  };
  for (const char* text : bad) {
    std::string error;
    EXPECT_FALSE(mtdd::control::parse_usage_state(text, &error).has_value()) << text;
    EXPECT_FALSE(error.empty()) << text;
  }
}

TEST(UsageStateTest, SaveIsPrivateAtomicAndLoadsBack) {
  TempDir dir;
  const std::filesystem::path path = dir.file("usage.json");
  UsageMap usage;
  usage["alice"] = UsageRecord{987654321, 1700000123};
  std::string error;
  ASSERT_TRUE(mtdd::control::save_usage_state(path, usage, error)) << error;
  EXPECT_EQ(mode_of(path.string()), 0600U);

  UsageMap loaded;
  ASSERT_TRUE(mtdd::control::load_usage_state(path, loaded, error)) << error;
  EXPECT_EQ(loaded, usage);

  // Overwriting leaves no temp files behind.
  usage["alice"].used_bytes = 1;
  ASSERT_TRUE(mtdd::control::save_usage_state(path, usage, error)) << error;
  std::size_t files = 0;
  for (const auto& entry : std::filesystem::directory_iterator(dir.path())) {
    (void)entry;
    ++files;
  }
  EXPECT_EQ(files, 1U);
}

TEST(UsageStateTest, MissingFileIsEmptyAndUnsafeFilesAreRejected) {
  TempDir dir;
  UsageMap loaded{{"stale", UsageRecord{1, 1}}};
  std::string error;
  EXPECT_TRUE(mtdd::control::load_usage_state(dir.file("none.json"), loaded, error));
  EXPECT_TRUE(loaded.empty());

  // Group/other-readable file.
  const std::string open_file = dir.file("open.json");
  {
    std::ofstream out(open_file);
    out << R"({"version":1,"users":{}})";
  }
  ::chmod(open_file.c_str(), 0644);
  EXPECT_FALSE(mtdd::control::load_usage_state(open_file, loaded, error));
  EXPECT_NE(error.find("permissions"), std::string::npos);

  // Symlink.
  const std::string real = dir.file("real.json");
  {
    std::ofstream out(real);
    out << R"({"version":1,"users":{}})";
  }
  ::chmod(real.c_str(), 0600);
  const std::string link = dir.file("link.json");
  ASSERT_EQ(::symlink(real.c_str(), link.c_str()), 0);
  EXPECT_FALSE(mtdd::control::load_usage_state(link, loaded, error));
  UsageMap usage;
  EXPECT_FALSE(mtdd::control::save_usage_state(link, usage, error));

  // Corrupt content.
  const std::string corrupt = dir.file("corrupt.json");
  {
    std::ofstream out(corrupt);
    out << "{broken";
  }
  ::chmod(corrupt.c_str(), 0600);
  EXPECT_FALSE(mtdd::control::load_usage_state(corrupt, loaded, error));
}

TEST(UsageStateTest, KeeperRestoresKnownUsersIgnoresUnknownAndFlushes) {
  TempDir dir;
  const std::string path = dir.file("usage.json");
  UsageMap seed;
  seed["alice"] = UsageRecord{5000, 1700000000};
  seed["ghost"] = UsageRecord{9, 9};  // not in the user store
  std::string error;
  ASSERT_TRUE(mtdd::control::save_usage_state(path, seed, error)) << error;

  auto store = open_store_or_throw(dir.file("users.json"));
  CreateUserRequest request;
  request.name = "alice";
  request.secret = kHexA;
  ASSERT_TRUE(store.create_user(request).ok());

  Statistics stats;
  {
    UsageStateKeeper keeper(path, stats, store, std::chrono::milliseconds(50));
    keeper.load();
    EXPECT_EQ(stats.user("alice")->quota_used_bytes(), 5000U);
    EXPECT_EQ(stats.user("alice")->quota_reset_at(), 1700000000);
    EXPECT_EQ(stats.snapshot().users.count("ghost"), 0U);

    keeper.start();
    stats.user("alice")->add_payload(Direction::client_to_server, 1);
    // The periodic thread picks the change up on its own.
    bool seen = false;
    for (int i = 0; i < 100 && !seen; ++i) {
      std::this_thread::sleep_for(20ms);
      UsageMap now;
      if (mtdd::control::load_usage_state(path, now, error) && now.count("alice") != 0) {
        seen = now.at("alice").used_bytes == 5001;
      }
    }
    EXPECT_TRUE(seen);
    // A change right before stop() is covered by the final flush.
    stats.user("alice")->add_payload(Direction::server_to_client, 9);
    keeper.stop();
  }
  UsageMap final_state;
  ASSERT_TRUE(mtdd::control::load_usage_state(path, final_state, error)) << error;
  EXPECT_EQ(final_state.at("alice").used_bytes, 5010U);
  EXPECT_EQ(final_state.count("ghost"), 0U) << "unknown users are never written back";
}

TEST(UsageStateTest, KeeperFailsClosedOnCorruptFile) {
  TempDir dir;
  const std::string path = dir.file("usage.json");
  {
    std::ofstream out(path);
    out << "garbage";
  }
  ::chmod(path.c_str(), 0600);
  auto store = open_store_or_throw(dir.file("users.json"));
  Statistics stats;
  UsageStateKeeper keeper(path, stats, store);
  EXPECT_THROW(keeper.load(), std::runtime_error);
}

TEST(UsageStateTest, EmptyPathKeeperIsInert) {
  TempDir dir;
  auto store = open_store_or_throw(dir.file("users.json"));
  Statistics stats;
  UsageStateKeeper keeper({}, stats, store);
  keeper.load();
  keeper.start();
  EXPECT_TRUE(keeper.flush());
  keeper.stop();
}

}  // namespace
