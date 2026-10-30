#pragma once

// Private persistence of per-user quota counters. The file is deliberately
// separate from users.json: writing users.json bumps the store revision and
// every ETag, while usage changes continuously.
//
//   {"version":1,"users":{"alice":{"used":123,"reset_at":1700000000}}}
//
// Parsing is strict (exact keys, exact version, unsigned/non-negative values).
// Users that no longer exist in the store are ignored on load and never saved.

#include <mtdd/control.hpp>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <filesystem>
#include <map>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <thread>

namespace mtdd::control {

struct UsageRecord {
  uint64_t used_bytes{0};
  int64_t reset_at{0};  // unix seconds, 0 = never reset
  bool operator==(const UsageRecord&) const = default;
};
using UsageMap = std::map<std::string, UsageRecord>;

// Strict parse. On failure returns nullopt and (optionally) a short reason.
std::optional<UsageMap> parse_usage_state(std::string_view text,
                                          std::string* error = nullptr);
std::string serialize_usage_state(const UsageMap& usage);

// A missing file is an empty map (success). A symlink, non-regular file, file
// owned by another user, group/other-accessible file or malformed content is
// an error.
bool load_usage_state(const std::filesystem::path& path, UsageMap& out,
                      std::string& error);
// Atomic temp+rename in the target directory, mode 0600, fsync of file and
// directory.
bool save_usage_state(const std::filesystem::path& path, const UsageMap& usage,
                      std::string& error);

// Restores counters at startup and flushes them periodically and on stop().
// An empty path keeps everything in memory (all operations are no-ops).
class UsageStateKeeper {
 public:
  UsageStateKeeper(std::filesystem::path path, Statistics& stats, UserStore& users,
                   std::chrono::milliseconds interval = std::chrono::seconds(60));
  ~UsageStateKeeper();
  UsageStateKeeper(const UsageStateKeeper&) = delete;
  UsageStateKeeper& operator=(const UsageStateKeeper&) = delete;

  // Startup only. Throws std::runtime_error on an unsafe or corrupt file: a
  // silent reset would hand every user a fresh quota.
  void load();
  // Starts the flush thread (no-op without a path or when already started).
  void start();
  // Stops the thread and performs one final flush. Idempotent.
  void stop() noexcept;
  // Synchronous flush; false on I/O failure (counted, retried at next tick).
  bool flush() noexcept;
  uint64_t failures() const noexcept;

 private:
  void run();

  std::filesystem::path path_;
  Statistics& stats_;
  UserStore& users_;
  std::chrono::milliseconds interval_;
  std::mutex mutex_;  // guards thread control and serialises flush()
  std::condition_variable wake_;
  bool stopping_{false};
  bool started_{false};
  std::thread thread_;
  UsageMap last_written_;
  bool have_written_{false};
  std::atomic<uint64_t> failures_{0};
};

}  // namespace mtdd::control
