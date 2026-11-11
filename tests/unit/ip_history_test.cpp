// Tests for mtdd::control::IpHistory: HLL correctness, calendar rotation,
// persistence safety and bounded cost. Written against the HIST-001 contract.
#include <mtdd/ip_history.hpp>

#include <fcntl.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <limits>
#include <span>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>

#include "../../src/control/ip_history_internal.hpp"

namespace {

using mtdd::control::IpHistory;
using mtdd::control::IpHistorySnapshot;
namespace detail = mtdd::control::detail;

// AddressSanitizer intentionally retains quarantined allocations, so process
// RSS is not a meaningful fixed-memory signal there. The normal build asserts
// the bound; LeakSanitizer covers leaks in the sanitizer build.
#if defined(__SANITIZE_ADDRESS__)
#define MTDD_TEST_ASAN 1
#elif defined(__has_feature)
#if __has_feature(address_sanitizer)
#define MTDD_TEST_ASAN 1
#endif
#endif
#ifndef MTDD_TEST_ASAN
#define MTDD_TEST_ASAN 0
#endif

// 2030 timestamps keep the monotonic effective time deterministic; the module
// constructor itself uses the real clock.
constexpr int64_t kTue1030 = 1894098600;        // Tue 2030-01-08 10:30:00Z
constexpr int64_t kTue1100 = 1894100400;        // Tue 2030-01-08 11:00:00Z
constexpr int64_t kWed0000 = 1894147200;        // Wed 2030-01-09 00:00:00Z
constexpr int64_t kMonDay0000 = 1893974400;     // Mon 2030-01-07 00:00:00Z
constexpr int64_t kNextMon0000 = 1894579200;    // Mon 2030-01-14 00:00:00Z
constexpr int64_t kSun235959 = 1894579199;      // Sun 2030-01-13 23:59:59Z
constexpr int64_t kOldWeek0000 = 1578268800;    // Mon 2020-01-06 00:00:00Z
constexpr int64_t kOldHour0100 = 1578272400;    // Mon 2020-01-06 01:00:00Z

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

class TempDir {
 public:
  TempDir() {
    std::error_code error;
    const char* configured = std::getenv("MTDD_TEST_TMPDIR");
    const std::filesystem::path base = configured ? std::filesystem::path(configured)
                                                   : std::filesystem::temp_directory_path();
    std::filesystem::create_directories(base, error);
    if (error) throw std::runtime_error("cannot create test temporary directory");
    std::string pattern = (base / "mtdd-ip-history-XXXXXX").string();
    std::vector<char> buffer(pattern.begin(), pattern.end());
    buffer.push_back('\0');
    char* made = ::mkdtemp(buffer.data());
    if (made == nullptr) throw std::runtime_error("mkdtemp failed");
    path_ = made;
  }
  ~TempDir() {
    std::error_code error;
    std::filesystem::remove_all(path_, error);
  }
  TempDir(const TempDir&) = delete;
  TempDir& operator=(const TempDir&) = delete;

  const std::filesystem::path& path() const { return path_; }
  std::filesystem::path file(std::string_view name) const { return path_ / name; }

 private:
  std::filesystem::path path_;
};

IpHistory::Ip make_ip(uint32_t value) {
  IpHistory::Ip ip{};
  ip[0] = 0x20;
  ip[1] = 0x01;
  ip[2] = 0x0d;
  ip[3] = 0xb8;
  for (size_t i = 0; i < 4; ++i) {
    ip[12 + i] = static_cast<uint8_t>((value >> (8 * (3 - i))) & 0xff);
  }
  return ip;
}

detail::HistoryDigest digest_from_value(uint64_t value) {
  detail::HistoryDigest digest{};
  for (size_t i = 0; i < 8; ++i) {
    digest[7 - i] = static_cast<uint8_t>((value >> (8 * i)) & 0xff);
  }
  return digest;
}

void write_text(const std::filesystem::path& path, std::string_view text,
                mode_t mode = 0600) {
  const int fd = ::open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, mode);
  if (fd < 0) throw std::runtime_error("cannot create test file");
  size_t offset = 0;
  while (offset < text.size()) {
    const ssize_t written = ::write(fd, text.data() + offset, text.size() - offset);
    if (written <= 0) {
      ::close(fd);
      throw std::runtime_error("cannot write test file");
    }
    offset += static_cast<size_t>(written);
  }
  ::close(fd);
  if (::chmod(path.c_str(), mode) != 0) throw std::runtime_error("chmod failed");
}

std::string read_text(const std::filesystem::path& path) {
  std::ifstream stream(path, std::ios::binary);
  if (!stream) throw std::runtime_error("cannot read test file");
  return std::string(std::istreambuf_iterator<char>(stream),
                     std::istreambuf_iterator<char>());
}

uint32_t file_mode(const std::filesystem::path& path) {
  struct stat st {};
  if (::stat(path.c_str(), &st) != 0) return 0xffffffffu;
  return static_cast<uint32_t>(st.st_mode & 07777);
}

std::string hex_text(std::span<const uint8_t> data) {
  static constexpr char kHex[] = "0123456789abcdef";
  std::string out;
  out.reserve(data.size() * 2);
  for (const uint8_t byte : data) {
    out.push_back(kHex[byte >> 4]);
    out.push_back(kHex[byte & 0x0f]);
  }
  return out;
}

// Pins a deterministic HMAC key so cardinality assertions are reproducible;
// production keys are random and the HLL relative standard error (~3.25%)
// applies instead. The helper also exercises loading a valid private file.
std::filesystem::path pinned_state(TempDir& directory, std::string_view name,
                                   uint8_t seed) {
  const std::filesystem::path path = directory.file(name);
  {
    IpHistory history(path);
    if (!history.flush()) throw std::runtime_error("seed flush failed");
  }
  nlohmann::json root = nlohmann::json::parse(read_text(path));
  std::array<uint8_t, 32> key{};
  for (size_t i = 0; i < key.size(); ++i) {
    key[i] = static_cast<uint8_t>(seed + i * 7);
  }
  root["key"] = hex_text(key);
  write_text(path, root.dump() + "\n");
  return path;
}

// Bounded child wait: a regression that blocks in the constructor must fail the
// test instead of hanging the whole suite. Returns the wait status, -1 on
// waitpid failure, or -2 after SIGKILLing a timed-out child.
int wait_for_child_bounded(pid_t child, std::chrono::milliseconds timeout) {
  const auto deadline = std::chrono::steady_clock::now() + timeout;
  int status = 0;
  while (true) {
    const pid_t done = ::waitpid(child, &status, WNOHANG);
    if (done == child) return status;
    if (done < 0) return -1;
    if (std::chrono::steady_clock::now() >= deadline) {
      ::kill(child, SIGKILL);
      ::waitpid(child, &status, 0);
      return -2;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(5));
  }
}

uint64_t resident_bytes() {
  std::ifstream stream("/proc/self/statm");
  uint64_t total_pages = 0;
  uint64_t resident_pages = 0;
  if (!(stream >> total_pages >> resident_pages)) return 0;
  (void)total_pages;
  return resident_pages * static_cast<uint64_t>(::sysconf(_SC_PAGESIZE));
}

// ---------------------------------------------------------------------------
// Empty state and calendar math
// ---------------------------------------------------------------------------

TEST(IpHistory, EmptySnapshotIsZeroAndMemoryOnly) {
  IpHistory history;
  const IpHistorySnapshot snapshot = history.snapshot();
  EXPECT_EQ(snapshot.hour, 0U);
  EXPECT_EQ(snapshot.day, 0U);
  EXPECT_EQ(snapshot.week, 0U);
  EXPECT_FALSE(snapshot.persistence_enabled);
  EXPECT_EQ(snapshot.persistence_failures, 0U);
  EXPECT_EQ(snapshot.hour_started_at % 3600, 0);
  EXPECT_EQ(snapshot.day_started_at % 86400, 0);
  EXPECT_EQ(snapshot.week_started_at % 86400, 0);
  EXPECT_LE(snapshot.week_started_at, snapshot.day_started_at);
  EXPECT_LE(snapshot.day_started_at, snapshot.hour_started_at);
  EXPECT_GT(snapshot.collection_started_at, 0);
}

TEST(IpHistory, CalendarStartsAreUtcWithIsoMondayWeek) {
  const detail::CalendarStarts tuesday = detail::calendar_starts(kTue1030);
  EXPECT_EQ(tuesday.hour, kTue1030 - 1800);
  EXPECT_EQ(tuesday.day, 1894060800);       // Tue 2030-01-08 00:00:00Z
  EXPECT_EQ(tuesday.week, kMonDay0000);     // Mon 2030-01-07 00:00:00Z

  const detail::CalendarStarts sunday = detail::calendar_starts(kSun235959);
  EXPECT_EQ(sunday.week, kMonDay0000);      // ISO week still the previous Monday

  const detail::CalendarStarts monday = detail::calendar_starts(kNextMon0000);
  EXPECT_EQ(monday.week, kNextMon0000);
  EXPECT_EQ(monday.day, kNextMon0000);
  EXPECT_EQ(monday.hour, kNextMon0000);
}

// ---------------------------------------------------------------------------
// Observation semantics
// ---------------------------------------------------------------------------

TEST(IpHistory, SameIpObservedRepeatedlyIsIdempotent) {
  IpHistory history;
  const IpHistory::Ip ip = make_ip(7);
  ASSERT_TRUE(history.observe(ip));
  const IpHistorySnapshot once = history.snapshot();
  ASSERT_EQ(once.hour, 1U);
  for (int i = 0; i < 1000; ++i) ASSERT_TRUE(history.observe(ip));
  const IpHistorySnapshot repeated = history.snapshot();
  EXPECT_EQ(repeated.hour, once.hour);
  EXPECT_EQ(repeated.day, once.day);
  EXPECT_EQ(repeated.week, once.week);
}

TEST(IpHistory, CallerOwnsAddressNormalizationAndPortsAreNotPartOfIp) {
  // Pinned key: exact two-key estimates must not depend on random register
  // collisions at tiny cardinality.
  TempDir directory;
  IpHistory history(pinned_state(directory, "normalization.json", 0x31));
  IpHistory::Ip native_v4{};
  native_v4[0] = 192;
  native_v4[1] = 0;
  native_v4[2] = 2;
  native_v4[3] = 1;
  IpHistory::Ip mapped{};
  mapped[10] = 0xff;
  mapped[11] = 0xff;
  mapped[12] = 192;
  mapped[13] = 0;
  mapped[14] = 2;
  mapped[15] = 1;
  ASSERT_TRUE(history.observe(native_v4));
  ASSERT_TRUE(history.observe(mapped));
  // The type has no port and no implicit v4/v4-mapped folding: two canonical
  // forms are two distinct keys until the caller normalizes.
  EXPECT_EQ(history.snapshot().hour, 2U);
  ASSERT_TRUE(history.observe(native_v4));
  EXPECT_EQ(history.snapshot().hour, 2U);
}

TEST(IpHistory, SnapshotDoesNotRotate) {
  IpHistory history;
  ASSERT_TRUE(history.rotate(kTue1030));
  ASSERT_TRUE(history.observe(make_ip(1)));
  const IpHistorySnapshot first = history.snapshot();
  const IpHistorySnapshot second = history.snapshot();
  EXPECT_EQ(first.hour, 1U);
  EXPECT_EQ(second.hour, 1U);
  // Snapshot must not advance to the real clock and reset the future period.
  EXPECT_EQ(first.hour_started_at, detail::calendar_starts(kTue1030).hour);
  EXPECT_EQ(second.hour_started_at, first.hour_started_at);
}

// ---------------------------------------------------------------------------
// Rotation
// ---------------------------------------------------------------------------

TEST(IpHistory, RotateOnlyReportsActualPeriodChanges) {
  IpHistory history;
  EXPECT_TRUE(history.rotate(kTue1030));   // real-clock periods differ
  EXPECT_FALSE(history.rotate(kTue1030));
  EXPECT_FALSE(history.rotate(kTue1030 + 60));
  EXPECT_TRUE(history.rotate(kTue1100));
  EXPECT_FALSE(history.rotate(kTue1100));
}

TEST(IpHistory, HourDayAndWeekResetsWithDuplicateAcrossPeriods) {
  // Pinned key: the exact 1/2 estimates below are then reproducible instead of
  // depending on a ~1/1024 register collision between two distinct IPs.
  TempDir directory;
  IpHistory history(pinned_state(directory, "calendar.json", 0x21));
  const IpHistory::Ip a = make_ip(1);
  const IpHistory::Ip b = make_ip(2);
  ASSERT_TRUE(history.rotate(kTue1030));
  ASSERT_TRUE(history.observe(a));
  IpHistorySnapshot snapshot = history.snapshot();
  EXPECT_EQ(snapshot.hour, 1U);
  EXPECT_EQ(snapshot.day, 1U);
  EXPECT_EQ(snapshot.week, 1U);

  // Hour reset keeps day/week.
  ASSERT_TRUE(history.rotate(kTue1100));
  snapshot = history.snapshot();
  EXPECT_EQ(snapshot.hour, 0U);
  EXPECT_EQ(snapshot.day, 1U);
  EXPECT_EQ(snapshot.week, 1U);
  EXPECT_EQ(snapshot.hour_started_at, kTue1100);

  // Re-observing the same IP is not a duplicate in the new hour but is already
  // present in the day/week sketches.
  ASSERT_TRUE(history.observe(a));
  snapshot = history.snapshot();
  EXPECT_EQ(snapshot.hour, 1U);
  EXPECT_EQ(snapshot.day, 1U);
  EXPECT_EQ(snapshot.week, 1U);
  ASSERT_TRUE(history.observe(b));
  snapshot = history.snapshot();
  EXPECT_EQ(snapshot.hour, 2U);
  EXPECT_EQ(snapshot.day, 2U);
  EXPECT_EQ(snapshot.week, 2U);

  // Day reset also resets the hour; the ISO week survives until Monday.
  ASSERT_TRUE(history.rotate(kWed0000));
  snapshot = history.snapshot();
  EXPECT_EQ(snapshot.hour, 0U);
  EXPECT_EQ(snapshot.day, 0U);
  EXPECT_EQ(snapshot.week, 2U);
  EXPECT_EQ(snapshot.day_started_at, kWed0000);

  // Next Monday resets the week too.
  ASSERT_TRUE(history.rotate(kNextMon0000));
  snapshot = history.snapshot();
  EXPECT_EQ(snapshot.hour, 0U);
  EXPECT_EQ(snapshot.day, 0U);
  EXPECT_EQ(snapshot.week, 0U);
  EXPECT_EQ(snapshot.week_started_at, kNextMon0000);
}

TEST(IpHistory, WeekResetsAtMondayMidnightNotBefore) {
  IpHistory history;
  ASSERT_TRUE(history.rotate(kSun235959));
  ASSERT_TRUE(history.observe(make_ip(1)));
  EXPECT_EQ(history.snapshot().week, 1U);
  EXPECT_FALSE(history.rotate(kSun235959 + 1 - 86400));  // same week, earlier day
  EXPECT_EQ(history.snapshot().week, 1U);
  ASSERT_TRUE(history.rotate(kNextMon0000));
  const IpHistorySnapshot snapshot = history.snapshot();
  EXPECT_EQ(snapshot.week, 0U);
  EXPECT_EQ(snapshot.week_started_at, kNextMon0000);
}

TEST(IpHistory, BackwardClockDoesNotResetOrResurrect) {
  IpHistory history;
  const IpHistory::Ip ip = make_ip(9);
  ASSERT_TRUE(history.rotate(kTue1030));
  ASSERT_TRUE(history.observe(ip));
  ASSERT_TRUE(history.rotate(kNextMon0000));
  ASSERT_TRUE(history.observe(ip));
  const IpHistorySnapshot forward = history.snapshot();
  ASSERT_EQ(forward.hour, 1U);
  ASSERT_EQ(forward.day, 1U);
  ASSERT_EQ(forward.week, 1U);
  ASSERT_EQ(forward.hour_started_at, kNextMon0000);

  // A jump back to the previous Tuesday must neither reset nor restore old
  // periods: the effective timestamp stays at its maximum.
  EXPECT_FALSE(history.rotate(kTue1030));
  const IpHistorySnapshot backward = history.snapshot();
  EXPECT_EQ(backward.hour, 1U);
  EXPECT_EQ(backward.day, 1U);
  EXPECT_EQ(backward.week, 1U);
  EXPECT_EQ(backward.hour_started_at, forward.hour_started_at);
  EXPECT_FALSE(history.rotate(kNextMon0000 - 3600));
  EXPECT_EQ(history.snapshot().hour, 1U);
}

TEST(IpHistory, AbsurdTimestampsAreClampedWithoutOverflow) {
  IpHistory history;
  EXPECT_TRUE(history.rotate(std::numeric_limits<int64_t>::max()));
  IpHistorySnapshot snapshot = history.snapshot();
  EXPECT_GE(snapshot.week_started_at, 0);
  EXPECT_EQ(snapshot.week_started_at % 86400, 0);
  EXPECT_LE(snapshot.week_started_at, snapshot.day_started_at);
  EXPECT_LE(snapshot.day_started_at, snapshot.hour_started_at);
  EXPECT_TRUE(history.observe(make_ip(1)));
  EXPECT_EQ(history.snapshot().hour, 1U);
  // The monotonic effective time is already saturated, so odd/negative values
  // cannot rewind or reset the period.
  EXPECT_FALSE(history.rotate(std::numeric_limits<int64_t>::min()));
  EXPECT_FALSE(history.rotate(0));
  snapshot = history.snapshot();
  EXPECT_EQ(snapshot.hour, 1U);
  EXPECT_GE(snapshot.hour_started_at, 0);
}

TEST(IpHistory, CollectionStartSurvivesRotation) {
  IpHistory history;
  const int64_t started = history.snapshot().collection_started_at;
  ASSERT_TRUE(history.rotate(kTue1030));
  ASSERT_TRUE(history.rotate(kNextMon0000));
  const IpHistorySnapshot snapshot = history.snapshot();
  EXPECT_EQ(snapshot.collection_started_at, started);
}

// ---------------------------------------------------------------------------
// HLL reference math
// ---------------------------------------------------------------------------

TEST(IpHistory, HmacMatchesRfc4231TestCaseTwo) {
  static constexpr char kKeyText[] = "Jefe";
  static constexpr char kDataText[] = "what do ya want for nothing?";
  const std::span<const uint8_t> key(
      reinterpret_cast<const uint8_t*>(kKeyText), sizeof(kKeyText) - 1);
  const std::span<const uint8_t> data(
      reinterpret_cast<const uint8_t*>(kDataText), sizeof(kDataText) - 1);
  detail::HistoryDigest digest{};
  ASSERT_TRUE(detail::hmac_sha256(key, data, digest));
  const std::string hex = [&] {
    static constexpr char kHex[] = "0123456789abcdef";
    std::string out;
    out.reserve(digest.size() * 2);
    for (const uint8_t byte : digest) {
      out.push_back(kHex[byte >> 4]);
      out.push_back(kHex[byte & 0x0f]);
    }
    return out;
  }();
  EXPECT_EQ(hex,
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
}

TEST(IpHistory, HllIndexAndRankBoundaries) {
  const detail::HistoryDigest zero = digest_from_value(0);
  EXPECT_EQ(detail::hll_index(zero), 0U);
  EXPECT_EQ(detail::hll_rank(zero), detail::kHistoryMaxRank);

  const detail::HistoryDigest one = digest_from_value(1);
  EXPECT_EQ(detail::hll_index(one), 0U);
  EXPECT_EQ(detail::hll_rank(one), 54U);

  const detail::HistoryDigest top_remainder = digest_from_value(1ull << 53);
  EXPECT_EQ(detail::hll_index(top_remainder), 0U);
  EXPECT_EQ(detail::hll_rank(top_remainder), 1U);

  const detail::HistoryDigest all_ones =
      digest_from_value(std::numeric_limits<uint64_t>::max());
  EXPECT_EQ(detail::hll_index(all_ones), 1023U);
  EXPECT_EQ(detail::hll_rank(all_ones), 1U);

  const detail::HistoryDigest full_index = digest_from_value(1023ull << 54);
  EXPECT_EQ(detail::hll_index(full_index), 1023U);
  EXPECT_EQ(detail::hll_rank(full_index), detail::kHistoryMaxRank);

  const detail::HistoryDigest tenth_bit = digest_from_value(1ull << 10);
  EXPECT_EQ(detail::hll_index(tenth_bit), 0U);
  EXPECT_EQ(detail::hll_rank(tenth_bit), 44U);
  EXPECT_LE(detail::hll_rank(tenth_bit), detail::kHistoryMaxRank);
}

TEST(IpHistory, HllEstimateUsesLinearCountingForSmallCounts) {
  detail::HistoryRegisters registers{};
  EXPECT_DOUBLE_EQ(detail::hll_estimate(registers), 0.0);

  registers[0] = 1;
  // 1024 * ln(1024 / 1023), the standard linear-counting reference.
  EXPECT_NEAR(detail::hll_estimate(registers),
              1024.0 * std::log(1024.0 / 1023.0), 1e-9);

  detail::HistoryRegisters half{};
  for (size_t i = 0; i < 512; ++i) half[i] = 1;
  EXPECT_NEAR(detail::hll_estimate(half), 1024.0 * std::log(2.0), 1e-6);

  detail::HistoryRegisters saturated{};
  saturated.fill(1);
  EXPECT_GT(detail::hll_estimate(saturated), 0.0);
}

// ---------------------------------------------------------------------------
// Cardinality and cost
// ---------------------------------------------------------------------------

TEST(IpHistory, HundredThousandUniqueIpsWithinToleranceAndSnapshotCost) {
  TempDir directory;
  IpHistory history(pinned_state(directory, "perf-100k.json", 0x11));
  constexpr uint32_t kCount = 100'000;
  const auto start = std::chrono::steady_clock::now();
  bool admitted = true;
  for (uint32_t i = 0; i < kCount && admitted; ++i) {
    admitted = history.observe(make_ip(i));
  }
  const auto observed = std::chrono::steady_clock::now();
  ASSERT_TRUE(admitted);
  const double observe_ms =
      std::chrono::duration<double, std::milli>(observed - start).count();
  const IpHistorySnapshot snapshot = history.snapshot();
  const auto snapshotted = std::chrono::steady_clock::now();
  const double single_snapshot_us =
      std::chrono::duration<double, std::micro>(snapshotted - observed).count();
  constexpr int kSnapshotRepeats = 100;
  const auto repeat_start = std::chrono::steady_clock::now();
  uint64_t sink = 0;
  for (int i = 0; i < kSnapshotRepeats; ++i) sink += history.snapshot().hour;
  const auto repeat_end = std::chrono::steady_clock::now();
  const double snapshot_us =
      std::chrono::duration<double, std::micro>(repeat_end - repeat_start).count() /
      kSnapshotRepeats;
  (void)sink;
  std::cerr << "[perf] 100000 observes: " << observe_ms << " ms ("
            << (observe_ms * 1e6 / kCount) << " ns/op), snapshot: "
            << single_snapshot_us << " us first, " << snapshot_us
            << " us avg over " << kSnapshotRepeats << std::endl;
  EXPECT_NEAR(static_cast<double>(snapshot.hour), static_cast<double>(kCount),
              static_cast<double>(kCount) * 0.05);
  EXPECT_NEAR(static_cast<double>(snapshot.day), static_cast<double>(kCount),
              static_cast<double>(kCount) * 0.05);
  std::cerr << "[perf] estimates hour/day/week: " << snapshot.hour << "/"
            << snapshot.day << "/" << snapshot.week << std::endl;
}

TEST(IpHistory, OneMillionUniqueIpsBoundedAndFixedMemory) {
  TempDir directory;
  IpHistory history(pinned_state(directory, "perf-1m.json", 0x5a));
  constexpr uint32_t kCount = 1'000'000;
  const uint64_t rss_before = resident_bytes();
  const auto start = std::chrono::steady_clock::now();
  bool admitted = true;
  for (uint32_t i = 0; i < kCount && admitted; ++i) {
    admitted = history.observe(make_ip(i));
  }
  const auto observed = std::chrono::steady_clock::now();
  ASSERT_TRUE(admitted);
  const uint64_t rss_after = resident_bytes();
  const double observe_ms =
      std::chrono::duration<double, std::milli>(observed - start).count();
  const IpHistorySnapshot snapshot = history.snapshot();
  std::cerr << "[perf] 1000000 observes: " << observe_ms << " ms ("
            << (observe_ms * 1e6 / kCount) << " ns/op), rss delta: "
            << (rss_after - rss_before) / 1024 << " KiB, estimate: "
            << snapshot.hour << std::endl;
  EXPECT_NEAR(static_cast<double>(snapshot.hour), static_cast<double>(kCount),
              static_cast<double>(kCount) * 0.05);
  EXPECT_LT(snapshot.hour, 1'200'000U);
  EXPECT_EQ(snapshot.week, snapshot.hour);
  if (!MTDD_TEST_ASAN && rss_before != 0 && rss_after >= rss_before) {
    EXPECT_LT(rss_after - rss_before, 8ull * 1024 * 1024)
        << "HLL memory must stay fixed apart from normal allocator overhead";
  }
}

TEST(IpHistory, ConcurrentObserversMatchSingleThreadedReferenceExactly) {
  TempDir directory;
  constexpr uint32_t kPerThread = 1000;
  constexpr uint32_t kThreads = 8;  // matches the independent review probe
  constexpr uint32_t kTotal = kPerThread * kThreads;

  // Both instances get the same pinned key. HLL registers hold a per-register
  // maximum, so the final sketch is independent of observation order: a
  // single-threaded reference over the identical IP set must match exactly.
  // Any lost/duplicated update in the concurrent path shows up as a mismatch
  // instead of being absorbed by an estimator tolerance.
  const std::filesystem::path reference_path =
      pinned_state(directory, "concurrency-reference.json", 0x41);
  const std::filesystem::path concurrent_path =
      pinned_state(directory, "concurrency-live.json", 0x41);
  IpHistory reference(reference_path);
  IpHistory concurrent(concurrent_path);
  for (uint32_t i = 0; i < kTotal; ++i) {
    ASSERT_TRUE(reference.observe(make_ip(i)));
  }
  const IpHistorySnapshot expected = reference.snapshot();
  ASSERT_GT(expected.hour, kTotal / 2);  // not an empty or collapsed sketch

  std::vector<std::thread> workers;
  workers.reserve(kThreads);
  for (uint32_t thread = 0; thread < kThreads; ++thread) {
    workers.emplace_back([&concurrent, thread] {
      for (uint32_t i = 0; i < kPerThread; ++i) {
        EXPECT_TRUE(concurrent.observe(make_ip(thread * kPerThread + i)));
      }
    });
  }
  for (int i = 0; i < 50; ++i) {
    const IpHistorySnapshot live = concurrent.snapshot();
    EXPECT_LE(live.hour, kTotal + 1000);
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
  }
  for (std::thread& worker : workers) worker.join();

  const IpHistorySnapshot actual = concurrent.snapshot();
  EXPECT_EQ(actual.hour, expected.hour);
  EXPECT_EQ(actual.day, expected.day);
  EXPECT_EQ(actual.week, expected.week);

  // Compare the sketches themselves, not just the estimate: a lost update that
  // happens not to move the estimate would still show up in the registers.
  ASSERT_TRUE(reference.flush());
  ASSERT_TRUE(concurrent.flush());
  const nlohmann::json reference_state =
      nlohmann::json::parse(read_text(reference_path));
  const nlohmann::json live_state =
      nlohmann::json::parse(read_text(concurrent_path));
  EXPECT_EQ(live_state["hour_registers"], reference_state["hour_registers"]);
  EXPECT_EQ(live_state["day_registers"], reference_state["day_registers"]);
  EXPECT_EQ(live_state["week_registers"], reference_state["week_registers"]);
}

// ---------------------------------------------------------------------------
// Persistence
// ---------------------------------------------------------------------------

TEST(IpHistory, ExplicitFlushIsSafeWithoutPersistence) {
  IpHistory history;
  EXPECT_TRUE(history.flush());
  EXPECT_FALSE(history.snapshot().persistence_enabled);
}

TEST(IpHistory, RestartPreservesSketchesKeyAndCollectionStart) {
  TempDir directory;
  const std::filesystem::path path = directory.file("unique-ips.json");
  IpHistorySnapshot before;
  int64_t collection_started = 0;
  {
    IpHistory history(path);
    EXPECT_TRUE(history.snapshot().persistence_enabled);
    for (uint32_t i = 0; i < 500; ++i) ASSERT_TRUE(history.observe(make_ip(i)));
    ASSERT_TRUE(history.flush());
    before = history.snapshot();
    collection_started = before.collection_started_at;
    EXPECT_EQ(file_mode(path), 0600U);
    // HLL estimate for 500 distinct keys, not an exact count.
    EXPECT_NEAR(static_cast<double>(before.hour), 500.0, 50.0);
  }
  IpHistory restarted(path);
  const IpHistorySnapshot after = restarted.snapshot();
  EXPECT_EQ(after.hour, before.hour);
  EXPECT_EQ(after.day, before.day);
  EXPECT_EQ(after.week, before.week);
  EXPECT_EQ(after.hour_started_at, before.hour_started_at);
  EXPECT_EQ(after.day_started_at, before.day_started_at);
  EXPECT_EQ(after.week_started_at, before.week_started_at);
  EXPECT_EQ(after.collection_started_at, collection_started);
  EXPECT_EQ(after.persistence_failures, 0U);
  // Re-observing a previously seen IP after restart must be idempotent, which
  // only holds when the persisted HMAC key was reused.
  ASSERT_TRUE(restarted.observe(make_ip(0)));
  const IpHistorySnapshot duplicate = restarted.snapshot();
  EXPECT_EQ(duplicate.hour, before.hour);
  EXPECT_EQ(duplicate.day, before.day);
  EXPECT_EQ(duplicate.week, before.week);
}

TEST(IpHistory, StalePeriodsInStateFileAreClearedNotResurrected) {
  TempDir directory;
  const std::filesystem::path path = directory.file("unique-ips.json");
  int64_t original_collection_start = 0;
  {
    IpHistory history(path);
    for (uint32_t i = 0; i < 10; ++i) ASSERT_TRUE(history.observe(make_ip(i)));
    original_collection_start = history.snapshot().collection_started_at;
    ASSERT_TRUE(history.flush());
  }
  nlohmann::json root = nlohmann::json::parse(read_text(path));
  root["hour_started_at"] = kOldHour0100;
  root["day_started_at"] = kOldWeek0000;
  root["week_started_at"] = kOldWeek0000;
  const std::string edited = root.dump() + "\n";
  write_text(path, edited);

  IpHistory history(path);
  const IpHistorySnapshot snapshot = history.snapshot();
  EXPECT_EQ(snapshot.hour, 0U);
  EXPECT_EQ(snapshot.day, 0U);
  EXPECT_EQ(snapshot.week, 0U);
  EXPECT_EQ(snapshot.collection_started_at, original_collection_start);
  EXPECT_NE(snapshot.hour_started_at, kOldHour0100);
  EXPECT_EQ(snapshot.hour_started_at % 3600, 0);
  EXPECT_GT(snapshot.week_started_at, kOldWeek0000);
}

TEST(IpHistory, BackgroundCheckpointWritesWithoutExplicitFlush) {
  TempDir directory;
  const std::filesystem::path path = directory.file("unique-ips.json");
  IpHistory history(path);
  ASSERT_TRUE(history.observe(make_ip(3)));
  const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
  bool written = false;
  while (std::chrono::steady_clock::now() < deadline) {
    std::error_code error;
    if (std::filesystem::exists(path, error) && !error &&
        std::filesystem::file_size(path, error) > 0 && !error) {
      written = true;
      break;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
  }
  EXPECT_TRUE(written) << "background checkpoint did not run within 5s";
  EXPECT_TRUE(history.flush());
}

TEST(IpHistory, StateFileContainsNoRawAddresses) {
  TempDir directory;
  const std::filesystem::path path = directory.file("unique-ips.json");
  IpHistory history(path);
  const IpHistory::Ip distinctive = {0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04,
                                     0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c};
  ASSERT_TRUE(history.observe(distinctive));
  ASSERT_TRUE(history.flush());
  const std::string text = read_text(path);
  EXPECT_EQ(text.find("deadbeef"), std::string::npos);
  EXPECT_EQ(text.find("DEADBEEF"), std::string::npos);
  EXPECT_EQ(text.find("222.173.190.239"), std::string::npos);
  EXPECT_EQ(text.find("dead:beef"), std::string::npos);
}

TEST(IpHistory, CheckpointFailureCountsAndPreservesPreviousFile) {
  if (::geteuid() == 0) GTEST_SKIP() << "permission checks are bypassed for root";
  TempDir directory;
  const std::filesystem::path path = directory.file("unique-ips.json");
  IpHistory history(path);
  for (uint32_t i = 0; i < 5; ++i) ASSERT_TRUE(history.observe(make_ip(i)));
  ASSERT_TRUE(history.flush());
  const std::string durable = read_text(path);
  const IpHistorySnapshot before = history.snapshot();

  ASSERT_EQ(::chmod(directory.path().c_str(), 0500), 0);
  // A single new address can land on an occupied HLL register with a lower or
  // equal rank, leaving the sketch unchanged and making the flush a no-op.
  // Observe enough distinct addresses that at least one register must move.
  for (uint32_t i = 1000; i < 1032; ++i) ASSERT_TRUE(history.observe(make_ip(i)));
  EXPECT_FALSE(history.flush());
  const IpHistorySnapshot failed = history.snapshot();
  EXPECT_EQ(failed.persistence_failures, 1U);
  EXPECT_GE(failed.hour, before.hour);
  EXPECT_EQ(failed.day_started_at, before.day_started_at);
  EXPECT_EQ(read_text(path), durable);

  ASSERT_EQ(::chmod(directory.path().c_str(), 0700), 0);
  EXPECT_TRUE(history.flush());
  const IpHistorySnapshot recovered = history.snapshot();
  EXPECT_EQ(recovered.persistence_failures, 1U);
  EXPECT_EQ(read_text(path).size(), durable.size());
  EXPECT_NE(read_text(path), durable);
}

TEST(IpHistory, MalformedStateFileIsRejected) {
  TempDir directory;
  const std::filesystem::path path = directory.file("unique-ips.json");
  write_text(path, "this is not json\n");
  EXPECT_THROW((void)IpHistory{path}, std::runtime_error);
}

TEST(IpHistory, OversizeStateFileIsRejected) {
  TempDir directory;
  const std::filesystem::path path = directory.file("unique-ips.json");
  write_text(path, std::string(70 * 1024, 'a'));
  EXPECT_THROW((void)IpHistory{path}, std::runtime_error);
}

TEST(IpHistory, SymlinkedStateFileIsRejected) {
  TempDir directory;
  const std::filesystem::path target = directory.file("target.json");
  {
    IpHistory history(target);
    ASSERT_TRUE(history.observe(make_ip(1)));
    ASSERT_TRUE(history.flush());
  }
  const std::filesystem::path link = directory.file("link.json");
  ASSERT_EQ(::symlink(target.c_str(), link.c_str()), 0);
  EXPECT_THROW((void)IpHistory{link}, std::runtime_error);

  const std::filesystem::path dangling = directory.file("dangling.json");
  ASSERT_EQ(::symlink(directory.file("missing.json").c_str(), dangling.c_str()), 0);
  EXPECT_THROW((void)IpHistory{dangling}, std::runtime_error);
}

TEST(IpHistory, FifoStatePathIsRejectedWithoutBlockingStartup) {
  TempDir directory;
  const std::filesystem::path path = directory.file("unique-ips.fifo");
  ASSERT_EQ(::mkfifo(path.c_str(), static_cast<mode_t>(0600)), 0);

  // Run the constructor in a child so a blocking open() (the regression this
  // guards against) is killed by the parent's watchdog instead of wedging the
  // suite. With O_NONBLOCK, the child must exit almost immediately.
  const pid_t child = ::fork();
  ASSERT_GE(child, 0) << "fork failed";
  if (child == 0) {
    int code = 2;
    try {
      IpHistory history(path);
      code = 1;  // must not construct successfully
    } catch (const std::runtime_error&) {
      code = 0;  // expected fail-closed
    } catch (...) {
      code = 3;
    }
    ::_exit(code);
  }

  const int status = wait_for_child_bounded(child, std::chrono::seconds(5));
  if (status == -2) FAIL() << "constructor blocked on a FIFO for more than 5s";
  ASSERT_NE(status, -1) << "waitpid failed";
  ASSERT_TRUE(WIFEXITED(status)) << "child did not exit normally";
  EXPECT_EQ(WEXITSTATUS(status), 0)
      << "FIFO path must throw std::runtime_error (1=constructed, 3=other throw)";
}

TEST(IpHistory, GroupOrOtherAccessIsRejected) {
  TempDir directory;
  for (const mode_t mode : {mode_t(0644), mode_t(0640), mode_t(0604), mode_t(0660)}) {
    const std::filesystem::path path =
        directory.file("unique-ips-" + std::to_string(mode) + ".json");
    write_text(path, "{\"version\":1}\n", mode);
    EXPECT_THROW((void)IpHistory{path}, std::runtime_error) << "mode " << mode;
  }
}

TEST(IpHistory, ExistingPrivateStateFileIsAccepted) {
  TempDir directory;
  const std::filesystem::path path = directory.file("unique-ips.json");
  {
    IpHistory history(path);
    ASSERT_TRUE(history.observe(make_ip(1)));
    ASSERT_TRUE(history.flush());
  }
  EXPECT_NO_THROW({
    IpHistory history(path);
    EXPECT_EQ(history.snapshot().hour, 1U);
  });
}

// ---------------------------------------------------------------------------
// "Active" sketches (IPs past the byte threshold) and state format v2
// ---------------------------------------------------------------------------

// 3 sigma of the HLL relative standard error: 3 * 1.04 / sqrt(1024).
constexpr double kThreeSigma = 3.0 * 1.04 / 32.0;

class IpHistoryAccuracy : public ::testing::TestWithParam<uint32_t> {};

TEST_P(IpHistoryAccuracy, SeenAndActiveEstimatesStayWithinThreeSigma) {
  const uint32_t count = GetParam();
  TempDir directory;
  IpHistory history(pinned_state(directory, "accuracy.json", 0x33));
  // Different key ranges: the two sketches are fed independently.
  for (uint32_t i = 0; i < count; ++i) {
    ASSERT_TRUE(history.observe(make_ip(i)));
    ASSERT_TRUE(history.observe_active(make_ip(0x100000 + i)));
  }
  const IpHistorySnapshot snapshot = history.snapshot();
  const double tolerance = static_cast<double>(count) * kThreeSigma;
  for (const uint64_t estimate :
       {snapshot.hour, snapshot.day, snapshot.week, snapshot.hour_active,
        snapshot.day_active, snapshot.week_active}) {
    EXPECT_NEAR(static_cast<double>(estimate), static_cast<double>(count), tolerance);
  }
}

INSTANTIATE_TEST_SUITE_P(Distinct, IpHistoryAccuracy,
                         ::testing::Values(10'000U, 100'000U));

TEST(IpHistory, ActiveSketchesAreIndependentOfSeenAndIdempotent) {
  TempDir directory;
  IpHistory history(pinned_state(directory, "active.json", 0x44));
  ASSERT_TRUE(history.observe_active(make_ip(1)));
  IpHistorySnapshot snapshot = history.snapshot();
  EXPECT_EQ(snapshot.hour, 0U);
  EXPECT_EQ(snapshot.hour_active, 1U);
  EXPECT_EQ(snapshot.day_active, 1U);
  EXPECT_EQ(snapshot.week_active, 1U);

  ASSERT_TRUE(history.observe(make_ip(1)));
  ASSERT_TRUE(history.observe(make_ip(2)));
  ASSERT_TRUE(history.observe_active(make_ip(1)));  // duplicate
  snapshot = history.snapshot();
  EXPECT_EQ(snapshot.hour, 2U);
  EXPECT_EQ(snapshot.hour_active, 1U);
}

TEST(IpHistory, ActiveSketchesRotateWithTheirPeriods) {
  TempDir directory;
  IpHistory history(pinned_state(directory, "active-rotate.json", 0x55));
  ASSERT_TRUE(history.rotate(kTue1030));
  ASSERT_TRUE(history.observe(make_ip(1)));
  ASSERT_TRUE(history.observe_active(make_ip(1)));
  ASSERT_TRUE(history.rotate(kTue1100));  // new hour only
  IpHistorySnapshot snapshot = history.snapshot();
  EXPECT_EQ(snapshot.hour_active, 0U);
  EXPECT_EQ(snapshot.day_active, 1U);
  EXPECT_EQ(snapshot.week_active, 1U);
  ASSERT_TRUE(history.rotate(kNextMon0000));  // new day and week
  snapshot = history.snapshot();
  EXPECT_EQ(snapshot.day_active, 0U);
  EXPECT_EQ(snapshot.week_active, 0U);
}

TEST(IpHistory, VersionTwoStateRoundTripsActiveSketches) {
  TempDir directory;
  const std::filesystem::path path = directory.file("unique-ips.json");
  IpHistorySnapshot before;
  {
    IpHistory history(path);
    for (uint32_t i = 0; i < 500; ++i) ASSERT_TRUE(history.observe(make_ip(i)));
    for (uint32_t i = 0; i < 200; ++i) ASSERT_TRUE(history.observe_active(make_ip(i)));
    ASSERT_TRUE(history.flush());
    before = history.snapshot();
  }
  const nlohmann::json root = nlohmann::json::parse(read_text(path));
  EXPECT_EQ(root["version"], 2);
  EXPECT_EQ(root["hour_active_registers"].get<std::string>().size(), 2048U);
  EXPECT_EQ(file_mode(path), 0600U);

  IpHistory restarted(path);
  const IpHistorySnapshot after = restarted.snapshot();
  EXPECT_EQ(after.hour, before.hour);
  EXPECT_EQ(after.hour_active, before.hour_active);
  EXPECT_EQ(after.day_active, before.day_active);
  EXPECT_EQ(after.week_active, before.week_active);
  EXPECT_NEAR(static_cast<double>(after.hour_active), 200.0, 25.0);
  // Same key after restart: re-observing keeps the active estimate unchanged.
  ASSERT_TRUE(restarted.observe_active(make_ip(7)));
  EXPECT_EQ(restarted.snapshot().hour_active, before.hour_active);
}

TEST(IpHistory, VersionOneStateLoadsWithEmptyActiveAndIsUpgradedOnCheckpoint) {
  TempDir directory;
  const std::filesystem::path path = directory.file("unique-ips.json");
  IpHistorySnapshot before;
  {
    IpHistory history(path);
    for (uint32_t i = 0; i < 300; ++i) ASSERT_TRUE(history.observe(make_ip(i)));
    ASSERT_TRUE(history.flush());
    before = history.snapshot();
  }
  nlohmann::json root = nlohmann::json::parse(read_text(path));
  root["version"] = 1;
  root.erase("hour_active_registers");
  root.erase("day_active_registers");
  root.erase("week_active_registers");
  write_text(path, root.dump() + "\n");

  {
    IpHistory history(path);
    const IpHistorySnapshot loaded = history.snapshot();
    EXPECT_EQ(loaded.hour, before.hour);
    EXPECT_EQ(loaded.day, before.day);
    EXPECT_EQ(loaded.week, before.week);
    EXPECT_EQ(loaded.hour_active, 0U);
    EXPECT_EQ(loaded.day_active, 0U);
    EXPECT_EQ(loaded.week_active, 0U);
    ASSERT_TRUE(history.observe_active(make_ip(5)));
    ASSERT_TRUE(history.flush());
  }
  // The checkpoint rewrote the file as v2, keeping the seen sketches.
  EXPECT_EQ(nlohmann::json::parse(read_text(path))["version"], 2);
  IpHistory reopened(path);
  const IpHistorySnapshot upgraded = reopened.snapshot();
  EXPECT_EQ(upgraded.hour, before.hour);
  EXPECT_EQ(upgraded.hour_active, 1U);
}

TEST(IpHistory, VersionMismatchesInStateFileAreRejected) {
  TempDir directory;
  const std::filesystem::path path = directory.file("unique-ips.json");
  {
    IpHistory history(path);
    ASSERT_TRUE(history.flush());
  }
  const nlohmann::json valid = nlohmann::json::parse(read_text(path));

  nlohmann::json future = valid;
  future["version"] = 3;
  write_text(path, future.dump() + "\n");
  EXPECT_THROW((void)IpHistory{path}, std::runtime_error);

  nlohmann::json v1_with_active = valid;  // active fields did not exist in v1
  v1_with_active["version"] = 1;
  write_text(path, v1_with_active.dump() + "\n");
  EXPECT_THROW((void)IpHistory{path}, std::runtime_error);

  nlohmann::json v2_missing = valid;
  v2_missing.erase("week_active_registers");
  write_text(path, v2_missing.dump() + "\n");
  EXPECT_THROW((void)IpHistory{path}, std::runtime_error);
}

}  // namespace
