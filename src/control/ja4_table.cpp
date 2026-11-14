// Bounded process-wide JA4 fingerprint table; see Ja4Table in control.hpp.
#include "mtdd/control.hpp"

#include <algorithm>
#include <mutex>
#include <unordered_map>

namespace mtdd::control {

const char* to_string(Ja4Outcome outcome) noexcept {
  switch (outcome) {
    case Ja4Outcome::authenticated: return "authenticated";
    case Ja4Outcome::unauthenticated: return "unauthenticated";
    case Ja4Outcome::throttled: return "throttled";
    case Ja4Outcome::replay: return "replay";
    case Ja4Outcome::clock_skew: return "clock_skew";
  }
  return "unauthenticated";
}

struct Ja4Table::Impl {
  struct Slot {
    Entry entry;
    uint64_t touched{0};  // recency sequence, the eviction tie-breaker
  };
  explicit Impl(std::size_t cap) : capacity(std::max<std::size_t>(cap, 1)) {
    slots.reserve(capacity);
  }
  const std::size_t capacity;
  mutable std::mutex mutex;
  std::unordered_map<std::string, Slot> slots;
  uint64_t sequence{0};
  std::atomic<uint64_t> evictions{0};
  std::atomic<uint64_t> unsampled{0};
  std::atomic<int64_t> budget_second{0};
  std::atomic<uint32_t> budget_used{0};
};

Ja4Table::Ja4Table(std::size_t capacity) : impl_(std::make_unique<Impl>(capacity)) {}
Ja4Table::~Ja4Table() = default;

bool Ja4Table::sample_failed(int64_t unix_now) noexcept {
  int64_t current = impl_->budget_second.load(std::memory_order_relaxed);
  if (current != unix_now &&
      impl_->budget_second.compare_exchange_strong(current, unix_now,
                                                   std::memory_order_relaxed)) {
    impl_->budget_used.store(0, std::memory_order_relaxed);
  }
  if (impl_->budget_used.fetch_add(1, std::memory_order_relaxed) < kFailedPerSecond) {
    return true;
  }
  impl_->unsampled.fetch_add(1, std::memory_order_relaxed);
  return false;
}

void Ja4Table::record(std::string_view ja4, Ja4Outcome outcome, int64_t unix_now) {
  if (ja4.empty()) return;
  const auto index = static_cast<std::size_t>(outcome);
  if (index >= kJa4Outcomes) return;
  std::lock_guard<std::mutex> lock(impl_->mutex);
  auto found = impl_->slots.find(std::string(ja4));
  if (found == impl_->slots.end()) {
    if (impl_->slots.size() >= impl_->capacity) {
      // O(capacity) scan, only when a new fingerprint meets a full table.
      auto victim = impl_->slots.begin();
      for (auto it = impl_->slots.begin(); it != impl_->slots.end(); ++it) {
        if (it->second.entry.total < victim->second.entry.total ||
            (it->second.entry.total == victim->second.entry.total &&
             it->second.touched < victim->second.touched)) {
          victim = it;
        }
      }
      impl_->slots.erase(victim);
      impl_->evictions.fetch_add(1, std::memory_order_relaxed);
    }
    Impl::Slot slot;
    slot.entry.ja4 = std::string(ja4);
    slot.entry.first_seen = unix_now;
    found = impl_->slots.emplace(slot.entry.ja4, std::move(slot)).first;
  }
  Impl::Slot& slot = found->second;
  ++slot.entry.counts[index];
  ++slot.entry.total;
  slot.entry.last_seen = unix_now;
  slot.touched = ++impl_->sequence;
}

Ja4Table::Snapshot Ja4Table::snapshot() const {
  Snapshot out;
  out.capacity = impl_->capacity;
  {
    std::lock_guard<std::mutex> lock(impl_->mutex);
    out.entries.reserve(impl_->slots.size());
    for (const auto& [key, slot] : impl_->slots) out.entries.push_back(slot.entry);
  }
  out.evictions = evictions();
  out.unsampled = unsampled();
  std::sort(out.entries.begin(), out.entries.end(), [](const Entry& a, const Entry& b) {
    if (a.total != b.total) return a.total > b.total;
    if (a.last_seen != b.last_seen) return a.last_seen > b.last_seen;
    return a.ja4 < b.ja4;
  });
  return out;
}

std::size_t Ja4Table::size() const {
  std::lock_guard<std::mutex> lock(impl_->mutex);
  return impl_->slots.size();
}

uint64_t Ja4Table::evictions() const noexcept {
  return impl_->evictions.load(std::memory_order_relaxed);
}

uint64_t Ja4Table::unsampled() const noexcept {
  return impl_->unsampled.load(std::memory_order_relaxed);
}

}  // namespace mtdd::control
