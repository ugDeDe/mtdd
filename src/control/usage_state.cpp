#include <mtdd/usage_state.hpp>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <nlohmann/json.hpp>

#include <atomic>
#include <cerrno>
#include <cstring>
#include <limits>

namespace mtdd::control {
namespace {

using json = nlohmann::json;

constexpr uint64_t kMaxUsageFileBytes = 8ull * 1024 * 1024;

bool valid_user_name(std::string_view name) {
  if (name.empty() || name.size() > 64) return false;
  for (const char c : name) {
    const bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                    (c >= '0' && c <= '9') || c == '_' || c == '.' || c == '-';
    if (!ok) return false;
  }
  return true;
}

bool fail(std::string* error, const char* message) {
  if (error != nullptr) *error = message;
  return false;
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

struct FdGuard {
  int fd;
  ~FdGuard() {
    if (fd >= 0) ::close(fd);
  }
};

}  // namespace

std::optional<UsageMap> parse_usage_state(std::string_view text, std::string* error) {
  json root = json::parse(text.begin(), text.end(), nullptr, false);
  if (root.is_discarded() || !root.is_object()) {
    fail(error, "usage state is not a JSON object");
    return std::nullopt;
  }
  if (root.size() != 2 || !root.contains("version") || !root.contains("users")) {
    fail(error, "usage state must contain exactly \"version\" and \"users\"");
    return std::nullopt;
  }
  const json& version = root["version"];
  if (!version.is_number_unsigned() || version.get<uint64_t>() != 1) {
    fail(error, "unsupported usage state version");
    return std::nullopt;
  }
  const json& users = root["users"];
  if (!users.is_object()) {
    fail(error, "usage state \"users\" must be an object");
    return std::nullopt;
  }
  UsageMap out;
  for (const auto& [name, entry] : users.items()) {
    if (!valid_user_name(name)) {
      fail(error, "usage state contains an invalid user name");
      return std::nullopt;
    }
    if (!entry.is_object() || entry.size() != 2 || !entry.contains("used") ||
        !entry.contains("reset_at")) {
      fail(error, "usage state user must contain exactly \"used\" and \"reset_at\"");
      return std::nullopt;
    }
    const json& used = entry["used"];
    const json& reset_at = entry["reset_at"];
    if (!used.is_number_unsigned()) {
      fail(error, "usage state \"used\" must be an unsigned integer");
      return std::nullopt;
    }
    UsageRecord record;
    record.used_bytes = used.get<uint64_t>();
    if (reset_at.is_number_unsigned()) {
      const uint64_t raw = reset_at.get<uint64_t>();
      if (raw > static_cast<uint64_t>(std::numeric_limits<int64_t>::max())) {
        fail(error, "usage state \"reset_at\" is out of range");
        return std::nullopt;
      }
      record.reset_at = static_cast<int64_t>(raw);
    } else {
      fail(error, "usage state \"reset_at\" must be a non-negative integer");
      return std::nullopt;
    }
    out.emplace(name, record);
  }
  return out;
}

std::string serialize_usage_state(const UsageMap& usage) {
  json users = json::object();
  for (const auto& [name, record] : usage) {
    users[name] = json{{"used", record.used_bytes}, {"reset_at", record.reset_at}};
  }
  json root = json{{"version", 1}, {"users", std::move(users)}};
  std::string text = root.dump();
  text.push_back('\n');
  return text;
}

bool load_usage_state(const std::filesystem::path& path, UsageMap& out,
                      std::string& error) {
  out.clear();
  // O_NONBLOCK keeps open() from hanging on a FIFO; fstat() then rejects it.
  const int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
  if (fd < 0) {
    if (errno == ENOENT) return true;
    error = std::string("cannot open usage state: ") + std::strerror(errno);
    return false;
  }
  FdGuard guard{fd};
  struct stat st {};
  if (::fstat(fd, &st) != 0) {
    error = "cannot stat usage state";
    return false;
  }
  if (!S_ISREG(st.st_mode)) {
    error = "usage state is not a regular file";
    return false;
  }
  if (st.st_uid != ::geteuid()) {
    error = "usage state is not owned by the current user";
    return false;
  }
  if ((st.st_mode & (S_IRWXG | S_IRWXO)) != 0) {
    error = "usage state permissions are too broad";
    return false;
  }
  if (st.st_size < 0 || static_cast<uint64_t>(st.st_size) > kMaxUsageFileBytes) {
    error = "usage state is too large";
    return false;
  }
  std::string text(static_cast<size_t>(st.st_size), '\0');
  size_t offset = 0;
  while (offset < text.size()) {
    const ssize_t got = ::read(fd, text.data() + offset, text.size() - offset);
    if (got < 0) {
      if (errno == EINTR) continue;
      error = "cannot read usage state";
      return false;
    }
    if (got == 0) break;
    offset += static_cast<size_t>(got);
  }
  if (offset != text.size()) {
    error = "usage state is truncated";
    return false;
  }
  auto parsed = parse_usage_state(text, &error);
  if (!parsed) return false;
  out = std::move(*parsed);
  return true;
}

bool save_usage_state(const std::filesystem::path& path, const UsageMap& usage,
                      std::string& error) {
  const std::filesystem::path directory =
      path.parent_path().empty() ? std::filesystem::path(".") : path.parent_path();
  const std::string base = path.filename().string();
  if (base.empty()) {
    error = "usage state path has no file name";
    return false;
  }
  struct stat target {};
  if (::lstat(path.c_str(), &target) == 0) {
    if (S_ISLNK(target.st_mode) || !S_ISREG(target.st_mode)) {
      error = "usage state target is a symlink or not a regular file";
      return false;
    }
  } else if (errno != ENOENT) {
    error = std::string("cannot stat usage state: ") + std::strerror(errno);
    return false;
  }
  const std::string text = serialize_usage_state(usage);
  static std::atomic<uint64_t> sequence{0};
  std::string temp_path;
  int fd = -1;
  for (int attempt = 0; attempt < 8; ++attempt) {
    temp_path = (directory / ("." + base + ".tmp." + std::to_string(::getpid()) + "." +
                              std::to_string(sequence.fetch_add(1, std::memory_order_relaxed))))
                    .string();
    fd = ::open(temp_path.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
                static_cast<mode_t>(0600));
    if (fd >= 0) break;
    if (errno != EEXIST) break;
  }
  if (fd < 0) {
    error = std::string("cannot create usage state temp file: ") + std::strerror(errno);
    return false;
  }
  bool ok = ::fchmod(fd, static_cast<mode_t>(0600)) == 0;
  ok = ok && write_all(fd, text);
  ok = ok && ::fsync(fd) == 0;
  ::close(fd);
  if (!ok) {
    ::unlink(temp_path.c_str());
    error = "cannot write usage state temp file";
    return false;
  }
  if (::rename(temp_path.c_str(), path.c_str()) != 0) {
    ::unlink(temp_path.c_str());
    error = std::string("cannot publish usage state: ") + std::strerror(errno);
    return false;
  }
  const int dir_fd =
      ::open(directory.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
  if (dir_fd < 0) {
    error = "cannot open usage state directory";
    return false;
  }
  const bool synced = ::fsync(dir_fd) == 0;
  ::close(dir_fd);
  if (!synced) error = "cannot sync usage state directory";
  return synced;
}

UsageStateKeeper::UsageStateKeeper(std::filesystem::path path, Statistics& stats,
                                   UserStore& users, std::chrono::milliseconds interval)
    : path_(std::move(path)), stats_(stats), users_(users), interval_(interval) {}

UsageStateKeeper::~UsageStateKeeper() { stop(); }

void UsageStateKeeper::load() {
  if (path_.empty()) return;
  UsageMap stored;
  std::string error;
  if (!load_usage_state(path_, stored, error)) {
    throw std::runtime_error("usage state " + path_.string() + ": " + error);
  }
  const auto snapshot = users_.snapshot();
  for (const auto& [name, record] : stored) {
    if (!snapshot || snapshot->find(name) == nullptr) continue;  // unknown user
    const auto metrics = stats_.user(name);
    if (metrics) metrics->restore_quota(record.used_bytes, record.reset_at);
  }
}

void UsageStateKeeper::start() {
  if (path_.empty()) return;
  const std::lock_guard lock{mutex_};
  if (started_) return;
  started_ = true;
  stopping_ = false;
  thread_ = std::thread([this] { run(); });
}

void UsageStateKeeper::run() {
  std::unique_lock lock{mutex_};
  while (!stopping_) {
    if (wake_.wait_for(lock, interval_, [this] { return stopping_; })) break;
    lock.unlock();
    flush();
    lock.lock();
  }
}

void UsageStateKeeper::stop() noexcept {
  if (path_.empty()) return;
  std::thread joinable;
  {
    const std::lock_guard lock{mutex_};
    stopping_ = true;
    joinable = std::move(thread_);
  }
  wake_.notify_all();
  if (joinable.joinable()) joinable.join();
  bool was_started = false;
  {
    const std::lock_guard lock{mutex_};
    was_started = started_;
    started_ = false;
  }
  if (was_started) flush();
}

bool UsageStateKeeper::flush() noexcept {
  if (path_.empty()) return true;
  try {
    const std::lock_guard lock{mutex_};
    UsageMap current;
    const auto snapshot = users_.snapshot();
    for (const auto& [name, metrics] : stats_.snapshot().users) {
      if (!snapshot || snapshot->find(name) == nullptr) continue;  // deleted user
      current.emplace(name, UsageRecord{metrics.quota_used_bytes, metrics.quota_reset_at});
    }
    if (have_written_ && current == last_written_) return true;
    std::string error;
    if (!save_usage_state(path_, current, error)) {
      failures_.fetch_add(1, std::memory_order_relaxed);
      return false;
    }
    last_written_ = std::move(current);
    have_written_ = true;
    return true;
  } catch (...) {
    failures_.fetch_add(1, std::memory_order_relaxed);
    return false;
  }
}

uint64_t UsageStateKeeper::failures() const noexcept {
  return failures_.load(std::memory_order_relaxed);
}

}  // namespace mtdd::control
