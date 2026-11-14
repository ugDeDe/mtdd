// Process-wide JA4 table (Ja4Table) and GET /v1/ja4.
#include "../support/control_fixture.hpp"

#include <thread>

namespace {

using mtdd::control::Ja4Outcome;
using mtdd::control::Ja4Table;

constexpr const char* kReadToken = "unit-test-read-token-not-a-secret";

std::string fake_ja4(std::size_t i) {
  // 36 characters like a real JA4; distinct per i.
  char text[40];
  std::snprintf(text, sizeof(text), "t13d1516h2_%012zx_e5627efa2ab1", i);
  return text;
}

TEST(Ja4Table, CountsOutcomesPerFingerprint) {
  Ja4Table table(8);
  table.record("a", Ja4Outcome::authenticated, 100);
  table.record("a", Ja4Outcome::authenticated, 101);
  table.record("a", Ja4Outcome::replay, 102);
  table.record("b", Ja4Outcome::unauthenticated, 103);
  table.record("b", Ja4Outcome::throttled, 104);
  table.record("b", Ja4Outcome::clock_skew, 105);
  table.record("b", Ja4Outcome::unauthenticated, 106);
  table.record("", Ja4Outcome::authenticated, 107);  // unparseable: ignored
  const auto snap = table.snapshot();
  ASSERT_EQ(snap.entries.size(), 2u);
  EXPECT_EQ(snap.entries[0].ja4, "b");  // 4 > 3
  EXPECT_EQ(snap.entries[0].total, 4u);
  EXPECT_EQ(snap.entries[0].counts[static_cast<size_t>(Ja4Outcome::unauthenticated)], 2u);
  EXPECT_EQ(snap.entries[0].counts[static_cast<size_t>(Ja4Outcome::throttled)], 1u);
  EXPECT_EQ(snap.entries[0].counts[static_cast<size_t>(Ja4Outcome::clock_skew)], 1u);
  EXPECT_EQ(snap.entries[0].first_seen, 103);
  EXPECT_EQ(snap.entries[0].last_seen, 106);
  EXPECT_EQ(snap.entries[1].counts[static_cast<size_t>(Ja4Outcome::authenticated)], 2u);
  EXPECT_EQ(snap.entries[1].counts[static_cast<size_t>(Ja4Outcome::replay)], 1u);
  EXPECT_EQ(snap.evictions, 0u);
}

TEST(Ja4Table, ScannerFloodCannotEvictFrequentFingerprints) {
  Ja4Table table(16);
  // Four real client fingerprints with established counts.
  for (int round = 0; round < 10; ++round) {
    for (std::size_t i = 0; i < 4; ++i) table.record(fake_ja4(i), Ja4Outcome::authenticated, 1);
  }
  // A scanner mints 10 000 distinct fingerprints.
  for (std::size_t i = 1000; i < 11000; ++i) {
    table.record(fake_ja4(i), Ja4Outcome::unauthenticated, 2);
  }
  EXPECT_EQ(table.size(), 16u);
  const auto snap = table.snapshot();
  ASSERT_EQ(snap.entries.size(), 16u);
  for (std::size_t i = 0; i < 4; ++i) {
    EXPECT_EQ(snap.entries[i].total, 10u);
    EXPECT_EQ(snap.entries[i].ja4.substr(0, 11), "t13d1516h2_");
  }
  EXPECT_EQ(snap.evictions, 10000u - 12u);
  // A returning newcomer survives: the least recently seen count-1 entry goes.
  table.record(fake_ja4(1), Ja4Outcome::authenticated, 3);
  table.record("newcomer", Ja4Outcome::authenticated, 3);
  table.record("newcomer", Ja4Outcome::authenticated, 3);
  table.record(fake_ja4(20000), Ja4Outcome::unauthenticated, 4);
  bool found = false;
  for (const auto& entry : table.snapshot().entries) found |= entry.ja4 == "newcomer";
  EXPECT_TRUE(found);
}

TEST(Ja4Table, LeastRecentlySeenBreaksTies) {
  Ja4Table table(2);
  table.record("old", Ja4Outcome::authenticated, 1);
  table.record("new", Ja4Outcome::authenticated, 1);
  table.record("third", Ja4Outcome::authenticated, 1);  // evicts "old"
  const auto snap = table.snapshot();
  ASSERT_EQ(snap.entries.size(), 2u);
  for (const auto& entry : snap.entries) EXPECT_NE(entry.ja4, "old");
  EXPECT_EQ(snap.evictions, 1u);
}

TEST(Ja4Table, FailedSamplingBudgetPerSecond) {
  Ja4Table table;
  uint32_t allowed = 0;
  for (uint32_t i = 0; i < Ja4Table::kFailedPerSecond + 50; ++i) {
    allowed += table.sample_failed(1000) ? 1U : 0U;
  }
  EXPECT_EQ(allowed, Ja4Table::kFailedPerSecond);
  EXPECT_EQ(table.unsampled(), 50u);
  EXPECT_TRUE(table.sample_failed(1001));  // next second: budget renewed
}

TEST(Ja4Table, ConcurrentRecordingStaysBoundedAndConsistent) {
  Ja4Table table(32);
  constexpr int kThreads = 8;
  constexpr int kPerThread = 5000;
  std::vector<std::thread> threads;
  for (int t = 0; t < kThreads; ++t) {
    threads.emplace_back([&table, t] {
      for (int i = 0; i < kPerThread; ++i) {
        // Half the records hit one shared fingerprint, half are unique.
        if (i % 2 == 0) {
          table.record("shared", Ja4Outcome::authenticated, i);
        } else {
          table.record(fake_ja4(static_cast<std::size_t>(t * kPerThread + i)),
                       Ja4Outcome::unauthenticated, i);
        }
        if (i % 500 == 0) (void)table.snapshot();
        (void)table.sample_failed(i / 100);
      }
    });
  }
  for (auto& thread : threads) thread.join();
  const auto snap = table.snapshot();
  EXPECT_LE(snap.entries.size(), 32u);
  ASSERT_FALSE(snap.entries.empty());
  EXPECT_EQ(snap.entries[0].ja4, "shared");
  EXPECT_EQ(snap.entries[0].total, static_cast<uint64_t>(kThreads * kPerThread / 2));
  uint64_t unique_kept = 0;
  for (const auto& entry : snap.entries) unique_kept += entry.ja4 == "shared" ? 0 : 1;
  EXPECT_EQ(snap.evictions + unique_kept, static_cast<uint64_t>(kThreads * kPerThread / 2));
}

TEST(Ja4HttpTest, ListsTheTableForReadTokensWithoutFingerprintMetricLabels) {
  HttpOptions options;
  options.read_token = kReadToken;
  Harness h(StoreOptions{}, options);
  const auto empty = h.req("GET", "/v1/ja4", {}, kReadToken);
  ASSERT_EQ(empty.status, 200) << empty.body;
  const auto empty_data = parse_json(empty)["data"];
  EXPECT_TRUE(empty_data["fingerprints"].empty());
  EXPECT_EQ(empty_data["capacity"], Ja4Table::kDefaultCapacity);

  const std::string rare = fake_ja4(1);
  const std::string common = fake_ja4(2);
  h.stats().ja4().record(rare, Ja4Outcome::unauthenticated, 1893456000);
  for (int i = 0; i < 3; ++i) h.stats().ja4().record(common, Ja4Outcome::authenticated, 1893456000);
  h.stats().ja4().record(common, Ja4Outcome::replay, 1893456001);

  const auto listed = h.req("GET", "/v1/ja4", {}, kReadToken);
  ASSERT_EQ(listed.status, 200) << listed.body;
  const auto data = parse_json(listed)["data"];
  EXPECT_EQ(data["total"], 2);
  ASSERT_EQ(data["fingerprints"].size(), 2u);
  const auto& top = data["fingerprints"][0];
  EXPECT_EQ(top["ja4"], common);
  EXPECT_EQ(top["total"], 4);
  EXPECT_EQ(top["authenticated"], 3);
  EXPECT_EQ(top["replay"], 1);
  EXPECT_EQ(top["unauthenticated"], 0);
  EXPECT_EQ(top["throttled"], 0);
  EXPECT_EQ(top["clock_skew"], 0);
  EXPECT_EQ(top["last_seen"], "2030-01-01T00:00:01Z");
  EXPECT_EQ(data["fingerprints"][1]["ja4"], rare);

  const auto limited = parse_json(h.req("GET", "/v1/ja4?limit=1"))["data"];
  EXPECT_EQ(limited["fingerprints"].size(), 1u);
  EXPECT_EQ(h.req("GET", "/v1/ja4?limit=0").status, 400);
  EXPECT_EQ(h.req("GET", "/v1/ja4?bogus=1").status, 400);
  EXPECT_EQ(h.req("POST", "/v1/ja4").status, 405);
  EXPECT_EQ(h.req("GET", "/v1/ja4", {}, "").status, 401);
  EXPECT_EQ(h.req("GET", "/v1/ja4", {}, "wrong-token-value").status, 401);

  const auto metrics = h.req("GET", "/metrics").body;
  EXPECT_NE(metrics.find("mtdd_ja4_fingerprints 2\n"), std::string::npos);
  EXPECT_NE(metrics.find("mtdd_ja4_evictions_total 0\n"), std::string::npos);
  EXPECT_NE(metrics.find("mtdd_ja4_unsampled_total 0\n"), std::string::npos);
  EXPECT_EQ(metrics.find(common), std::string::npos);
  EXPECT_EQ(metrics.find("ja4=\""), std::string::npos);
}

TEST(Ja4HttpTest, SuspectRowsCarryTheirJa4) {
  Harness h;
  h.stats().set_suspect_lister([] {
    std::vector<Statistics::SuspectInfo> rows(2);
    rows[0].ip = "198.51.100.1";
    rows[0].hits[0] = 1;
    rows[0].matches = 1;
    rows[0].ja4 = "t13d1516h2_8daaf6152771_e5627efa2ab1";
    rows[1].ip = "198.51.100.2";
    rows[1].hits[0] = 1;
    rows[1].matches = 1;
    return rows;
  });
  const auto data = parse_json(h.req("GET", "/v1/suspects?sort=hits"))["data"];
  ASSERT_EQ(data["suspects"].size(), 2u);
  for (const auto& row : data["suspects"]) {
    if (row["ip"] == "198.51.100.1") {
      EXPECT_EQ(row["ja4"], "t13d1516h2_8daaf6152771_e5627efa2ab1");
    } else {
      EXPECT_TRUE(row["ja4"].is_null());
    }
  }
  h.stats().set_suspect_lister({});
}

}  // namespace
