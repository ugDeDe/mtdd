#include "../support/control_fixture.hpp"

// ClientHellos with a valid secret but a timestamp outside the window, by the
// client's clock relative to the server and by |skew| bucket. Every one of the
// fixed series is always present so "never seen" differs from "not reported".

namespace {

uint64_t skew_count(const Statistics& stats, const std::string& side, const std::string& bucket) {
  return stats.snapshot().hello_clock_skew_total.at(side).at(bucket);
}

TEST(ClockSkewStats, BucketsByDirectionAndMagnitude) {
  Statistics stats;
  // skew = server clock - client timestamp; positive = client clock behind.
  struct Case {
    int64_t skew;
    const char* side;
    const char* bucket;
  };
  const Case cases[] = {
      {121, "behind", "le_300s"},   {300, "behind", "le_300s"},
      {301, "behind", "le_600s"},   {600, "behind", "le_600s"},
      {601, "behind", "le_1200s"},  {1200, "behind", "le_1200s"},
      {1201, "behind", "gt_1200s"}, {4294967295LL, "behind", "gt_1200s"},
      {-121, "ahead", "le_300s"},   {-300, "ahead", "le_300s"},
      {-301, "ahead", "le_600s"},   {-600, "ahead", "le_600s"},
      {-601, "ahead", "le_1200s"},  {-1200, "ahead", "le_1200s"},
      {-1201, "ahead", "gt_1200s"}, {-4294967295LL, "ahead", "gt_1200s"},
  };
  for (const auto& c : cases) {
    SCOPED_TRACE(c.skew);
    const uint64_t before = skew_count(stats, c.side, c.bucket);
    stats.hello_clock_skew(c.skew);
    EXPECT_EQ(skew_count(stats, c.side, c.bucket), before + 1);
  }
  const auto snapshot = stats.snapshot();
  ASSERT_EQ(snapshot.hello_clock_skew_total.size(), 2U);
  for (const auto& [side, buckets] : snapshot.hello_clock_skew_total) {
    ASSERT_EQ(buckets.size(), 4U) << side;
    for (const auto& [bucket, value] : buckets) EXPECT_EQ(value, 2U) << side << " " << bucket;
  }
  // Not a handshake result of its own: the existing series are untouched.
  EXPECT_TRUE(snapshot.handshakes_by_result.empty());
}

TEST(ClockSkewStats, ExposedInPrometheusAndStatusJson) {
  Harness h;
  h.stats().hello_clock_skew(200);
  h.stats().hello_clock_skew(200);
  h.stats().hello_clock_skew(-5000);

  auto metrics = h.req("GET", "/metrics");
  ASSERT_EQ(metrics.status, 200);
  EXPECT_NE(metrics.body.find(
                "mtdd_handshake_clock_skew_total{client_clock=\"behind\",skew=\"le_300s\"} 2\n"),
            std::string::npos);
  EXPECT_NE(metrics.body.find(
                "mtdd_handshake_clock_skew_total{client_clock=\"ahead\",skew=\"gt_1200s\"} 1\n"),
            std::string::npos);
  EXPECT_NE(metrics.body.find(
                "mtdd_handshake_clock_skew_total{client_clock=\"ahead\",skew=\"le_600s\"} 0\n"),
            std::string::npos);
  std::size_t series = 0;
  for (std::size_t at = metrics.body.find("mtdd_handshake_clock_skew_total{");
       at != std::string::npos;
       at = metrics.body.find("mtdd_handshake_clock_skew_total{", at + 1)) {
    ++series;
  }
  EXPECT_EQ(series, 8U);

  auto response = h.req("GET", "/v1/status");
  ASSERT_EQ(response.status, 200);
  const auto data = parse_json(response)["data"];
  const auto& skew = data["handshake_clock_skew_total"];
  EXPECT_EQ(skew["behind"]["le_300s"], 2);
  EXPECT_EQ(skew["behind"]["gt_1200s"], 0);
  EXPECT_EQ(skew["ahead"]["gt_1200s"], 1);
  EXPECT_EQ(skew["ahead"]["le_1200s"], 0);
  // The handshake counters keep their meaning: nothing was recorded there.
  EXPECT_EQ(data["handshakes_total"], 0);
}

}  // namespace
