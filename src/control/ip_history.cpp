// Fixed-size calendar unique-IP history: three 1024-register HLL sketches with
// keyed HMAC-SHA256 hashing and optional atomic private checkpointing.
#include <mtdd/ip_history.hpp>

#include "ip_history_internal.hpp"

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <bit>
#include <cerrno>
#include <chrono>
#include <cmath>
#include <condition_variable>
#include <cstring>
#include <limits>
#include <mutex>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <utility>

#include <nlohmann/json.hpp>

namespace mtdd::control {
namespace {

using json = nlohmann::json;

constexpr size_t kKeyBytes = 32;
constexpr uint64_t kMaxStateFileBytes = 64ull * 1024;
constexpr uint64_t kMaxStateTimestamp = 253402300799;  // 9999-12-31T23:59:59Z
constexpr int64_t kSecondsPerHour = 3600;
constexpr int64_t kSecondsPerDay = 86400;
constexpr int64_t kSecondsPerWeek = 7 * kSecondsPerDay;
constexpr std::chrono::seconds kCheckpointInterval{60};
constexpr auto kCheckpointPoll = std::chrono::seconds(1);

char kDigestName[] = "SHA256";

int64_t current_unix_seconds() {
  return std::chrono::duration_cast<std::chrono::seconds>(
             std::chrono::system_clock::now().time_since_epoch())
      .count();
}

int hex_value(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

std::string hex_encode(std::span<const uint8_t> data) {
  static constexpr char kHex[] = "0123456789abcdef";
  std::string out(data.size() * 2, '\0');
  for (size_t i = 0; i < data.size(); ++i) {
    out[2 * i] = kHex[data[i] >> 4];
    out[2 * i + 1] = kHex[data[i] & 0x0f];
  }
  return out;
}

bool hex_decode(std::string_view text, std::span<uint8_t> out) {
  if (text.size() != out.size() * 2) return false;
  for (size_t i = 0; i < out.size(); ++i) {
    const int high = hex_value(text[2 * i]);
    const int low = hex_value(text[2 * i + 1]);
    if (high < 0 || low < 0) return false;
    out[i] = static_cast<uint8_t>((high << 4) | low);
  }
  return true;
}

// Fails closed on symlinked or non-directory components; creates missing
// components with owner-only mode 0700 (umask is overridden explicitly).
std::optional<std::string> ensure_directory(const std::string& dir) {
  if (dir.empty() || dir == ".") return std::nullopt;
  std::string current;
  size_t i = 0;
  if (dir.front() == '/') {
    current = "/";
    i = 1;
  }
  while (i <= dir.size()) {
    const size_t next = dir.find('/', i);
    const std::string component =
        dir.substr(i, next == std::string::npos ? std::string::npos : next - i);
    if (!component.empty()) {
      if (!current.empty() && current.back() != '/') current += '/';
      current += component;
      struct stat st {};
      if (::lstat(current.c_str(), &st) != 0) {
        if (errno != ENOENT) return "stat directory " + current;
        if (::mkdir(current.c_str(), static_cast<mode_t>(0700)) != 0) {
          return "mkdir " + current;
        }
        if (::chmod(current.c_str(), static_cast<mode_t>(0700)) != 0) {
          return "chmod " + current;
        }
      } else {
        if (S_ISLNK(st.st_mode)) {
          return "directory component is a symlink: " + current;
        }
        if (!S_ISDIR(st.st_mode)) {
          return "path component is not a directory: " + current;
        }
      }
    }
    if (next == std::string::npos) break;
    i = next + 1;
  }
  return std::nullopt;
}

bool write_all(int fd, std::string_view data) {
  size_t offset = 0;
  while (offset < data.size()) {
    const ssize_t written = ::write(fd, data.data() + offset, data.size() - offset);
    if (written < 0) {
      if (errno == EINTR) continue;
      return false;
    }
    if (written == 0) return false;
    offset += static_cast<size_t>(written);
  }
  return true;
}

struct StateImage {
  uint64_t version{2};
  std::array<uint8_t, kKeyBytes> key{};
  detail::HistoryRegisters hour{};
  detail::HistoryRegisters day{};
  detail::HistoryRegisters week{};
  // Version 2: IPs that crossed the byte threshold. Empty when loaded from v1.
  detail::HistoryRegisters hour_active{};
  detail::HistoryRegisters day_active{};
  detail::HistoryRegisters week_active{};
  int64_t hour_started_at{};
  int64_t day_started_at{};
  int64_t week_started_at{};
  int64_t collection_started_at{};
};

bool json_i64(const json& value, int64_t& out) {
  if (value.is_number_unsigned()) {
    const uint64_t raw = value.get<uint64_t>();
    if (raw > static_cast<uint64_t>(std::numeric_limits<int64_t>::max())) return false;
    out = static_cast<int64_t>(raw);
    return true;
  }
  if (value.is_number_integer()) {
    out = value.get<int64_t>();
    return true;
  }
  return false;
}

bool valid_timestamp(int64_t value) {
  return value >= 0 && value <= static_cast<int64_t>(kMaxStateTimestamp);
}

// Period starts must be aligned and internally consistent: hour inside its day,
// day inside its ISO week, week starting Monday 00:00 UTC.
bool valid_starts(int64_t hour, int64_t day, int64_t week) {
  if (!valid_timestamp(hour) || !valid_timestamp(day) || !valid_timestamp(week)) {
    return false;
  }
  if (hour % kSecondsPerHour != 0 || day % kSecondsPerDay != 0 ||
      week % kSecondsPerDay != 0) {
    return false;
  }
  if (hour < day || hour - day >= kSecondsPerDay) return false;
  if (day < week || day - week >= kSecondsPerWeek) return false;
  const int64_t days = week / kSecondsPerDay;
  const int64_t weekday = ((days + 3) % 7 + 7) % 7;  // 1970-01-01 was Thursday
  return weekday == 0;
}

bool decode_registers(std::string_view text, detail::HistoryRegisters& out) {
  if (text.size() != out.size() * 2) return false;
  for (size_t i = 0; i < out.size(); ++i) {
    const int high = hex_value(text[2 * i]);
    const int low = hex_value(text[2 * i + 1]);
    if (high < 0 || low < 0) return false;
    const int value = (high << 4) | low;
    if (value > detail::kHistoryMaxRank) return false;
    out[i] = static_cast<uint8_t>(value);
  }
  return true;
}

void parse_state(const std::string& text, StateImage& out) {
  const json root = json::parse(text, nullptr, false);
  if (root.is_discarded() || !root.is_object()) {
    throw std::runtime_error("ip history: state file is not a JSON object");
  }
  static constexpr std::array<std::string_view, 12> kAllowed = {
      "version",          "key",              "hour_registers",
      "day_registers",    "week_registers",   "hour_started_at",
      "day_started_at",   "week_started_at",  "collection_started_at",
      "hour_active_registers", "day_active_registers", "week_active_registers"};
  for (auto it = root.begin(); it != root.end(); ++it) {
    bool known = false;
    for (const std::string_view field : kAllowed) {
      if (it.key() == field) {
        known = true;
        break;
      }
    }
    if (!known) throw std::runtime_error("ip history: state file has an unknown field");
  }
  if (!root.contains("version") || !root["version"].is_number_unsigned()) {
    throw std::runtime_error("ip history: unsupported state file version");
  }
  const uint64_t version = root["version"].get<uint64_t>();
  if (version != 1 && version != 2) {
    throw std::runtime_error("ip history: unsupported state file version");
  }
  out.version = version;
  if (!root.contains("key") || !root["key"].is_string()) {
    throw std::runtime_error("ip history: state key is missing");
  }
  const std::string key_hex = root["key"].get<std::string>();
  if (!hex_decode(key_hex, out.key)) {
    throw std::runtime_error("ip history: state key is invalid");
  }
  struct RegisterField {
    const char* name;
    detail::HistoryRegisters* target;
    bool v2_only;
  };
  const std::array<RegisterField, 6> register_fields = {{
      {"hour_registers", &out.hour, false},
      {"day_registers", &out.day, false},
      {"week_registers", &out.week, false},
      {"hour_active_registers", &out.hour_active, true},
      {"day_active_registers", &out.day_active, true},
      {"week_active_registers", &out.week_active, true},
  }};
  for (const RegisterField& field : register_fields) {
    if (field.v2_only && version == 1) {
      // A v1 file predates the active sketches; they start empty.
      if (root.contains(field.name)) {
        throw std::runtime_error("ip history: state file has an unknown field");
      }
      continue;
    }
    if (!root.contains(field.name) || !root[field.name].is_string() ||
        !decode_registers(root[field.name].get<std::string>(), *field.target)) {
      throw std::runtime_error("ip history: state registers are invalid");
    }
  }
  int64_t hour = 0;
  int64_t day = 0;
  int64_t week = 0;
  int64_t collection = 0;
  if (!root.contains("hour_started_at") || !json_i64(root["hour_started_at"], hour) ||
      !root.contains("day_started_at") || !json_i64(root["day_started_at"], day) ||
      !root.contains("week_started_at") || !json_i64(root["week_started_at"], week) ||
      !root.contains("collection_started_at") ||
      !json_i64(root["collection_started_at"], collection) ||
      !valid_starts(hour, day, week) || !valid_timestamp(collection)) {
    throw std::runtime_error("ip history: state timestamps are invalid");
  }
  out.hour_started_at = hour;
  out.day_started_at = day;
  out.week_started_at = week;
  out.collection_started_at = collection;
}

std::string serialize_state(const StateImage& image) {
  json root;
  root["version"] = 2;
  root["key"] = hex_encode(image.key);
  root["hour_registers"] = hex_encode(image.hour);
  root["day_registers"] = hex_encode(image.day);
  root["week_registers"] = hex_encode(image.week);
  root["hour_active_registers"] = hex_encode(image.hour_active);
  root["day_active_registers"] = hex_encode(image.day_active);
  root["week_active_registers"] = hex_encode(image.week_active);
  root["hour_started_at"] = image.hour_started_at;
  root["day_started_at"] = image.day_started_at;
  root["week_started_at"] = image.week_started_at;
  root["collection_started_at"] = image.collection_started_at;
  std::string text = root.dump();
  text.push_back('\n');
  return text;
}

// Returns true when a state file was loaded. Missing files are a fresh start;
// anything else that is unsafe or malformed throws (fail closed).
bool read_state_file(const std::filesystem::path& path, StateImage& out) {
  // O_NONBLOCK makes open() return immediately for a FIFO at the configured
  // path; fstat() then rejects it as non-regular instead of startup blocking
  // until a writer appears. It has no effect on regular files.
  const int fd = ::open(path.c_str(),
                        O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
  if (fd < 0) {
    if (errno == ENOENT) return false;
    if (errno == ELOOP) {
      throw std::runtime_error("ip history: state file path is a symlink");
    }
    throw std::runtime_error(std::string("ip history: cannot open state file: ") +
                             std::strerror(errno));
  }
  struct FdGuard {
    int fd;
    ~FdGuard() {
      if (fd >= 0) ::close(fd);
    }
  } guard{fd};
  struct stat st {};
  if (::fstat(fd, &st) != 0) {
    throw std::runtime_error("ip history: cannot stat state file");
  }
  if (!S_ISREG(st.st_mode)) {
    throw std::runtime_error("ip history: state file is not a regular file");
  }
  if (st.st_uid != ::geteuid()) {
    throw std::runtime_error("ip history: state file is not owned by the current user");
  }
  if ((st.st_mode & (S_IRWXG | S_IRWXO)) != 0) {
    throw std::runtime_error("ip history: state file permissions are too broad");
  }
  if (st.st_size < 0 || static_cast<uint64_t>(st.st_size) > kMaxStateFileBytes) {
    throw std::runtime_error("ip history: state file is too large");
  }
  std::string text(static_cast<size_t>(st.st_size), '\0');
  size_t offset = 0;
  while (offset < text.size()) {
    const ssize_t got = ::read(fd, text.data() + offset, text.size() - offset);
    if (got < 0) {
      if (errno == EINTR) continue;
      throw std::runtime_error("ip history: cannot read state file");
    }
    if (got == 0) break;
    offset += static_cast<size_t>(got);
  }
  if (offset != text.size()) {
    throw std::runtime_error("ip history: state file is truncated");
  }
  parse_state(text, out);
  return true;
}

// Atomic temp+rename in the target directory. Existing paths that are symlinks
// or not regular files are rejected. Publication only happens on rename; every
// earlier failure leaves the previous file untouched.
bool write_state_file(const std::filesystem::path& path, const StateImage& image) {
  const std::filesystem::path directory =
      path.parent_path().empty() ? std::filesystem::path(".") : path.parent_path();
  const std::string base = path.filename().string();
  if (base.empty()) return false;
  struct stat target {};
  if (::lstat(path.c_str(), &target) == 0) {
    if (S_ISLNK(target.st_mode) || !S_ISREG(target.st_mode)) return false;
  } else if (errno != ENOENT) {
    return false;
  }
  const std::string text = serialize_state(image);
  static std::atomic<uint64_t> sequence{0};
  std::string temp_path;
  int fd = -1;
  for (int attempt = 0; attempt < 8; ++attempt) {
    temp_path =
        (directory / ("." + base + ".tmp." + std::to_string(::getpid()) + "." +
                      std::to_string(sequence.fetch_add(1, std::memory_order_relaxed))))
            .string();
    fd = ::open(temp_path.c_str(),
                O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
                static_cast<mode_t>(0600));
    if (fd >= 0) break;
    if (errno != EEXIST) return false;
  }
  if (fd < 0) return false;
  bool ok = ::fchmod(fd, static_cast<mode_t>(0600)) == 0;
  ok = ok && write_all(fd, text);
  ok = ok && ::fsync(fd) == 0;
  ::close(fd);
  if (!ok) {
    ::unlink(temp_path.c_str());
    return false;
  }
  if (::rename(temp_path.c_str(), path.c_str()) != 0) {
    ::unlink(temp_path.c_str());
    return false;
  }
  const int dir_fd =
      ::open(directory.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
  if (dir_fd < 0) return false;
  const bool synced = ::fsync(dir_fd) == 0;
  ::close(dir_fd);
  return synced;
}

// Reusable HMAC-SHA256 context. Not thread-safe by itself; IpHistory serializes
// access with its state mutex.
class Mac {
 public:
  Mac() noexcept {
    mac_ = EVP_MAC_fetch(nullptr, "HMAC", nullptr);
    if (mac_ != nullptr) ctx_ = EVP_MAC_CTX_new(mac_);
  }
  ~Mac() {
    if (ctx_ != nullptr) EVP_MAC_CTX_free(ctx_);
    if (mac_ != nullptr) EVP_MAC_free(mac_);
  }
  Mac(const Mac&) = delete;
  Mac& operator=(const Mac&) = delete;

  bool ok() const noexcept { return ctx_ != nullptr; }

  // Installs the long-lived HMAC key. IpHistory calls this once during
  // construction; every subsequent message reuses that key.
  bool set_key(std::span<const uint8_t> key) noexcept {
    return init(key.data(), key.size());
  }

  // Resets the MAC and reuses the key installed by set_key(). OpenSSL HMAC
  // supports key reuse when EVP_MAC_init() receives a null key.
  bool compute_next(std::span<const uint8_t> data,
                    detail::HistoryDigest& out) noexcept {
    return init(nullptr, 0) && finish(data, out);
  }

  bool compute(std::span<const uint8_t> key, std::span<const uint8_t> data,
               detail::HistoryDigest& out) noexcept {
    return init(key.data(), key.size()) && finish(data, out);
  }

 private:
  bool init(const uint8_t* key, size_t key_size) noexcept {
    if (ctx_ == nullptr) return false;
    OSSL_PARAM params[2];
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, kDigestName, 0);
    params[1] = OSSL_PARAM_construct_end();
    return EVP_MAC_init(ctx_, key, key_size, params) == 1;
  }

  bool finish(std::span<const uint8_t> data,
              detail::HistoryDigest& out) noexcept {
    size_t out_length = 0;
    out.fill(0);
    if (EVP_MAC_update(ctx_, data.data(), data.size()) != 1) return false;
    if (EVP_MAC_final(ctx_, out.data(), &out_length, out.size()) != 1) return false;
    return out_length == out.size();
  }

  EVP_MAC* mac_{nullptr};
  EVP_MAC_CTX* ctx_{nullptr};
};

uint64_t estimate_count(const detail::HistoryRegisters& registers) {
  const double value = detail::hll_estimate(registers);
  if (!(value > 0.0)) return 0;
  if (value >= 9.0e18) return std::numeric_limits<uint64_t>::max();
  return static_cast<uint64_t>(std::llround(value));
}

}  // namespace

namespace detail {

bool hmac_sha256(std::span<const uint8_t> key, std::span<const uint8_t> data,
                 HistoryDigest& out) noexcept {
  Mac mac;
  return mac.compute(key, data, out);
}

uint32_t hll_index(const HistoryDigest& digest) noexcept {
  uint64_t value = 0;
  for (size_t i = 0; i < 8; ++i) {
    value = (value << 8) | digest[i];
  }
  return static_cast<uint32_t>(value >> (64 - kHistoryIndexBits));
}

uint8_t hll_rank(const HistoryDigest& digest) noexcept {
  uint64_t value = 0;
  for (size_t i = 0; i < 8; ++i) {
    value = (value << 8) | digest[i];
  }
  const uint64_t remainder = value << kHistoryIndexBits;
  if (remainder == 0) return kHistoryMaxRank;
  return static_cast<uint8_t>(std::countl_zero(remainder) + 1);
}

double hll_estimate(const HistoryRegisters& registers) noexcept {
  constexpr double m = static_cast<double>(kHistoryRegisterCount);
  constexpr double alpha = 0.7213 / (1.0 + 1.079 / m);
  double harmonic_sum = 0.0;
  size_t zeros = 0;
  for (const uint8_t rank : registers) {
    harmonic_sum += std::ldexp(1.0, -static_cast<int>(rank));
    if (rank == 0) ++zeros;
  }
  if (!(harmonic_sum > 0.0)) return 0.0;
  const double raw = alpha * m * m / harmonic_sum;
  if (!std::isfinite(raw)) return 0.0;
  if (raw <= 2.5 * m && zeros > 0) {
    return m * std::log(m / static_cast<double>(zeros));
  }
  return std::max(raw, 0.0);
}

CalendarStarts calendar_starts(int64_t unix_seconds) noexcept {
  const auto floor_div = [](int64_t value, int64_t divisor) {
    int64_t quotient = value / divisor;
    if (value % divisor < 0) --quotient;
    return quotient;
  };
  CalendarStarts starts;
  const int64_t days = floor_div(unix_seconds, kSecondsPerDay);
  starts.hour = floor_div(unix_seconds, kSecondsPerHour) * kSecondsPerHour;
  starts.day = days * kSecondsPerDay;
  const int64_t weekday = ((days + 3) % 7 + 7) % 7;  // Monday == 0
  starts.week = (days - weekday) * kSecondsPerDay;
  return starts;
}

}  // namespace detail

struct IpHistory::Impl {
  Impl(std::filesystem::path path);
  ~Impl();

  bool rotate(int64_t unix_seconds);
  bool observe(const Ip& ip, bool active);
  IpHistorySnapshot snapshot() const;
  bool checkpoint(bool force);

  StateImage capture_locked() const;
  void checkpoint_loop();
  void maybe_checkpoint();

  mutable std::mutex mutex_;
  std::array<uint8_t, kKeyBytes> key_{};
  detail::HistoryRegisters hour_{};
  detail::HistoryRegisters day_{};
  detail::HistoryRegisters week_{};
  detail::HistoryRegisters hour_active_{};
  detail::HistoryRegisters day_active_{};
  detail::HistoryRegisters week_active_{};
  detail::CalendarStarts starts_{};
  int64_t collection_started_at_{};
  int64_t last_timestamp_{};
  uint64_t state_version_{1};
  uint64_t persisted_version_{0};
  uint64_t persistence_failures_{0};
  Mac mac_;

  const std::filesystem::path path_;
  const bool persistence_enabled_;

  std::mutex io_mutex_;
  std::chrono::steady_clock::time_point last_checkpoint_{};
  bool checkpointed_once_{false};

  std::mutex background_mutex_;
  std::condition_variable background_cv_;
  bool stop_{false};
  std::thread background_;
};

IpHistory::Impl::Impl(std::filesystem::path path)
    : path_(std::move(path)), persistence_enabled_(!path_.empty()) {
  if (!mac_.ok()) {
    throw std::runtime_error("ip history: HMAC-SHA256 initialization failed");
  }
  const int64_t now = current_unix_seconds();
  last_timestamp_ = now;
  starts_ = detail::calendar_starts(now);
  collection_started_at_ = now;
  if (persistence_enabled_) {
    const std::string directory =
        path_.parent_path().empty() ? "." : path_.parent_path().string();
    if (const auto error = ensure_directory(directory)) {
      throw std::runtime_error("ip history: " + *error);
    }
    StateImage loaded;
    if (read_state_file(path_, loaded)) {
      key_ = loaded.key;
      collection_started_at_ = loaded.collection_started_at;
      bool stale = false;
      if (loaded.hour_started_at == starts_.hour) {
        hour_ = loaded.hour;
        hour_active_ = loaded.hour_active;
      } else {
        stale = true;
      }
      if (loaded.day_started_at == starts_.day) {
        day_ = loaded.day;
        day_active_ = loaded.day_active;
      } else {
        stale = true;
      }
      if (loaded.week_started_at == starts_.week) {
        week_ = loaded.week;
        week_active_ = loaded.week_active;
      } else {
        stale = true;
      }
      // A v1 file is rewritten as v2 by the first checkpoint.
      persisted_version_ = (stale || loaded.version < 2) ? 0 : 1;
    } else if (RAND_bytes(key_.data(), static_cast<int>(key_.size())) != 1) {
      throw std::runtime_error("ip history: key generation failed");
    }
  } else if (RAND_bytes(key_.data(), static_cast<int>(key_.size())) != 1) {
    throw std::runtime_error("ip history: key generation failed");
  }
  // Start the checkpoint thread only after all throwing setup so a failure
  // cannot unwind past a joinable std::thread (which would terminate).
  if (!mac_.set_key(key_)) {
    throw std::runtime_error("ip history: HMAC key setup failed");
  }
  if (persistence_enabled_) {
    background_ = std::thread([this] { checkpoint_loop(); });
  }
}

IpHistory::Impl::~Impl() {
  if (background_.joinable()) {
    {
      std::lock_guard lock(background_mutex_);
      stop_ = true;
    }
    background_cv_.notify_all();
    background_.join();
  }
  if (persistence_enabled_) {
    try {
      checkpoint(true);
    } catch (...) {
      // Destructors must not throw; failures are already counted where possible.
    }
  }
  OPENSSL_cleanse(key_.data(), key_.size());
}

bool IpHistory::Impl::rotate(int64_t unix_seconds) {
  std::lock_guard lock(mutex_);
  // Clamp to the documented timestamp domain so calendar math cannot overflow;
  // productive callers pass a wall-clock value.
  const int64_t bounded =
      std::clamp<int64_t>(unix_seconds, 0, static_cast<int64_t>(kMaxStateTimestamp));
  const int64_t effective = std::max(last_timestamp_, bounded);
  last_timestamp_ = effective;
  const detail::CalendarStarts starts = detail::calendar_starts(effective);
  bool changed = false;
  if (starts.hour != starts_.hour) {
    hour_.fill(0);
    hour_active_.fill(0);
    starts_.hour = starts.hour;
    changed = true;
  }
  if (starts.day != starts_.day) {
    day_.fill(0);
    day_active_.fill(0);
    starts_.day = starts.day;
    changed = true;
  }
  if (starts.week != starts_.week) {
    week_.fill(0);
    week_active_.fill(0);
    starts_.week = starts.week;
    changed = true;
  }
  if (changed) ++state_version_;
  return changed;
}

bool IpHistory::Impl::observe(const Ip& ip, bool active) {
  std::lock_guard lock(mutex_);
  detail::HistoryDigest digest{};
  if (!mac_.compute_next(ip, digest)) return false;
  const uint32_t index = detail::hll_index(digest);
  const uint8_t rank = detail::hll_rank(digest);
  detail::HistoryRegisters& hour = active ? hour_active_ : hour_;
  detail::HistoryRegisters& day = active ? day_active_ : day_;
  detail::HistoryRegisters& week = active ? week_active_ : week_;
  bool changed = false;
  if (rank > hour[index]) {
    hour[index] = rank;
    changed = true;
  }
  if (rank > day[index]) {
    day[index] = rank;
    changed = true;
  }
  if (rank > week[index]) {
    week[index] = rank;
    changed = true;
  }
  if (changed) ++state_version_;
  return true;
}

StateImage IpHistory::Impl::capture_locked() const {
  StateImage image;
  image.key = key_;
  image.hour = hour_;
  image.day = day_;
  image.week = week_;
  image.hour_active = hour_active_;
  image.day_active = day_active_;
  image.week_active = week_active_;
  image.hour_started_at = starts_.hour;
  image.day_started_at = starts_.day;
  image.week_started_at = starts_.week;
  image.collection_started_at = collection_started_at_;
  return image;
}

IpHistorySnapshot IpHistory::Impl::snapshot() const {
  detail::HistoryRegisters hour;
  detail::HistoryRegisters day;
  detail::HistoryRegisters week;
  detail::HistoryRegisters hour_active;
  detail::HistoryRegisters day_active;
  detail::HistoryRegisters week_active;
  detail::CalendarStarts starts;
  int64_t collection = 0;
  uint64_t failures = 0;
  {
    std::lock_guard lock(mutex_);
    hour = hour_;
    day = day_;
    week = week_;
    hour_active = hour_active_;
    day_active = day_active_;
    week_active = week_active_;
    starts = starts_;
    collection = collection_started_at_;
    failures = persistence_failures_;
  }
  IpHistorySnapshot result;
  result.hour = estimate_count(hour);
  result.day = estimate_count(day);
  result.week = estimate_count(week);
  result.hour_active = estimate_count(hour_active);
  result.day_active = estimate_count(day_active);
  result.week_active = estimate_count(week_active);
  result.hour_started_at = starts.hour;
  result.day_started_at = starts.day;
  result.week_started_at = starts.week;
  result.collection_started_at = collection;
  result.persistence_failures = failures;
  result.persistence_enabled = persistence_enabled_;
  return result;
}

bool IpHistory::Impl::checkpoint(bool force) {
  if (!persistence_enabled_) return true;  // memory-only: nothing to persist
  try {
    std::unique_lock io_lock(io_mutex_);
    const auto now = std::chrono::steady_clock::now();
    if (!force && checkpointed_once_ &&
        now - last_checkpoint_ < kCheckpointInterval) {
      return true;  // rate-limited; state stays dirty for a later attempt
    }
    StateImage image;
    uint64_t version = 0;
    {
      std::lock_guard lock(mutex_);
      if (state_version_ == persisted_version_) return true;
      image = capture_locked();
      version = state_version_;
    }
    last_checkpoint_ = now;
    checkpointed_once_ = true;
    if (!write_state_file(path_, image)) {
      std::lock_guard lock(mutex_);
      ++persistence_failures_;
      return false;
    }
    {
      std::lock_guard lock(mutex_);
      if (version > persisted_version_) persisted_version_ = version;
    }
    return true;
  } catch (...) {
    std::lock_guard lock(mutex_);
    ++persistence_failures_;
    return false;
  }
}

void IpHistory::Impl::maybe_checkpoint() {
  {
    std::lock_guard lock(mutex_);
    if (state_version_ == persisted_version_) return;
  }
  checkpoint(false);
}

void IpHistory::Impl::checkpoint_loop() {
  std::unique_lock lock(background_mutex_);
  while (!stop_) {
    background_cv_.wait_for(lock, kCheckpointPoll, [this] { return stop_; });
    if (stop_) break;
    lock.unlock();
    maybe_checkpoint();
    lock.lock();
  }
}

IpHistory::IpHistory(std::filesystem::path path)
    : impl_(std::make_unique<Impl>(std::move(path))) {}

IpHistory::~IpHistory() = default;

bool IpHistory::rotate(int64_t unix_seconds) {
  return impl_->rotate(unix_seconds);
}

bool IpHistory::observe(const Ip& ip) { return impl_->observe(ip, false); }

bool IpHistory::observe_active(const Ip& ip) { return impl_->observe(ip, true); }

IpHistorySnapshot IpHistory::snapshot() const { return impl_->snapshot(); }

bool IpHistory::flush() { return impl_->checkpoint(true); }

}  // namespace mtdd::control
