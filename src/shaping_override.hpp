// Live media-shaping override (PATCH/DELETE /v1/shaping) on top of the rules
// from the config file. Header-only so main.cpp and the unit tests share it.
#pragma once

#include "mtdd/config.hpp"

#include <functional>
#include <mutex>
#include <optional>
#include <utility>

#include <nlohmann/json.hpp>

namespace mtdd {

// Effective rules = the API override when one is set, else the configured
// rules. Every change applies the effective rules through `apply` while the
// lock is held, so concurrent API calls and SIGHUP reloads reach the runtime
// in the same order as they change this state. Nothing is persisted: a
// restart returns to the config file.
class ShapingOverride {
public:
    using Apply = std::function<void(const ShapingConfig&)>;

    ShapingOverride(ShapingConfig configured, Apply apply)
        : configured_(std::move(configured)), apply_(std::move(apply)) {}

    // Applies the current effective rules (call once at startup if needed).
    void apply_effective() {
        const std::lock_guard lock{mutex_};
        apply_locked();
    }

    // Merges `patch` (a "shaping" object) onto the effective rules and makes
    // the result the override. Throws std::invalid_argument (state unchanged)
    // when the patch is invalid.
    void patch(const nlohmann::json& patch) {
        const std::lock_guard lock{mutex_};
        override_ = parse_shaping(patch, effective_locked());
        apply_locked();
    }

    // Drops the override; returns whether one was active.
    bool reset() {
        const std::lock_guard lock{mutex_};
        const bool had = override_.has_value();
        override_.reset();
        apply_locked();
        return had;
    }

    // New rules from a reloaded config file. They take effect only when no
    // override is active; returns true when an override keeps them out.
    bool reload(ShapingConfig configured) {
        const std::lock_guard lock{mutex_};
        configured_ = std::move(configured);
        apply_locked();
        return override_.has_value();
    }

    bool overridden() const {
        const std::lock_guard lock{mutex_};
        return override_.has_value();
    }

    ShapingConfig effective() const {
        const std::lock_guard lock{mutex_};
        return effective_locked();
    }

    // {"source": "config"|"api", "effective": {...}, "configured": {...}}
    nlohmann::json view() const {
        const std::lock_guard lock{mutex_};
        return {{"source", override_ ? "api" : "config"},
                {"effective", shaping_view(effective_locked())},
                {"configured", shaping_view(configured_)}};
    }

private:
    const ShapingConfig& effective_locked() const { return override_ ? *override_ : configured_; }
    void apply_locked() {
        if (apply_) apply_(effective_locked());
    }

    mutable std::mutex mutex_;
    ShapingConfig configured_;
    std::optional<ShapingConfig> override_;
    Apply apply_;
};

} // namespace mtdd
