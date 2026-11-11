// Calendar-bound unique-IP estimates for mtdd (global only, no per-user
// history). Two sets of three fixed 1024-register HyperLogLog sketches (~3 KiB per set,
// ~3.25% relative standard error, not a hard bound) count unique canonical
// client IPs for:
//   hour: current UTC hour
//   day:  current UTC midnight-based day
//   week: current ISO week (Monday 00:00 UTC)
// These are fixed calendar boundaries, not rolling windows.
// The "seen" set is fed by observe() (authenticated handshake); the "active" set
// by observe_active() (IP transferred at least the configured payload bytes).
// Both rotate together and use the same HMAC key.
//
// Only the caller advances periods through rotate(). observe() and snapshot()
// never rotate implicitly, so the runtime can seed long-lived active IPs after
// a boundary and get consistent counts. rotate() is monotonic in its argument:
// the effective time is the maximum timestamp seen since construction, so a
// backward wall-clock jump neither resurrects expired periods nor repeatedly
// resets the sketches. Periods advance only once the wall clock exceeds that
// maximum; after a backward jump the stored period start can be later than the
// current wall clock until it catches up.
//
// collection_started_at is the wall-clock second at which collection began. It
// is construction time for a fresh state file and is preserved across restarts;
// rotations never reset it.
//
// Persistence (non-empty path): one bounded background thread checkpoints dirty
// state at most once per 60 seconds, and the destructor performs one final
// checkpoint. Up to the last ~60 seconds may be lost on power loss. flush() is a
// synchronous checkpoint intended for tests and shutdown only; do not call it
// from the proxy reactor. Checkpoint failures increment persistence_failures and
// are retried; they never reset counts or terminate the process. The state file
// (state format version 2; version 1 files load with empty active sketches)
// stores only the random HMAC key, register arrays and timestamps: no IP
// addresses and no per-address data. Neither the key nor any address is logged.
//
// Thread-safe. Not copyable or movable. The constructor may throw
// std::runtime_error for invalid/unreadable state files, unsafe file ownership
// or permissions, or random-key/HMAC initialization failure (fail closed).
#pragma once

#include <array>
#include <cstdint>
#include <filesystem>
#include <memory>

namespace mtdd::control {

struct IpHistorySnapshot {
  uint64_t hour{};
  uint64_t day{};
  uint64_t week{};
  // Same periods, counting only IPs observed through observe_active().
  uint64_t hour_active{};
  uint64_t day_active{};
  uint64_t week_active{};
  int64_t hour_started_at{};
  int64_t day_started_at{};
  int64_t week_started_at{};
  int64_t collection_started_at{};
  uint64_t persistence_failures{};
  bool persistence_enabled{};
};

class IpHistory {
 public:
  // Canonical 16-byte address without port. The caller must normalize IPv4 and
  // IPv4-mapped IPv6 to one canonical form; this module does not guess.
  using Ip = std::array<uint8_t, 16>;

  // Empty path means memory-only mode (no background thread, no disk I/O).
  explicit IpHistory(std::filesystem::path path = {});
  ~IpHistory();

  IpHistory(const IpHistory&) = delete;
  IpHistory& operator=(const IpHistory&) = delete;
  IpHistory(IpHistory&&) = delete;
  IpHistory& operator=(IpHistory&&) = delete;

  // Advances the calendar periods for unix_seconds and clears any sketch whose
  // period changed. Returns true when at least one period was reset; the caller
  // must then seed all currently active IPs. Safe to call with an unchanged or
  // older timestamp (monotonic effective time, see the file comment).
  bool rotate(int64_t unix_seconds);

  // Hashes ip with the persisted key and updates all three sketches. Returns
  // true when the keyed hash and register update completed. Does not rotate.
  bool observe(const Ip& ip);
  // Same, for the "active" sketches only.
  bool observe_active(const Ip& ip);

  // Consistent copy of estimates and timestamps. Does not rotate or perform
  // I/O. Counts are HLL estimates of unique IPs, never unique people.
  IpHistorySnapshot snapshot() const;

  // Synchronous checkpoint. Returns true when no checkpoint was needed or it
  // succeeded. Outside the proxy reactor thread only.
  bool flush();

 private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

}  // namespace mtdd::control
