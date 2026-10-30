// mtdd data-plane runtime: one or more Linux epoll reactors that terminate
// FakeTLS on the client side and multiplex every logical client over shared,
// pooled Telegram Middle-End (ME) connections selected by exact signed DC.
//
// Threading model
// ---------------
// The constructor binds the proxy listener on the calling thread. With
// workers=1 run() drives the whole reactor on the calling thread; with N>1 it
// binds N SO_REUSEPORT listeners, starts N-1 worker threads and drives reactor
// 0 on the calling thread. Each reactor owns its clients, ME pool and buffers.
// The only cross-reactor state is admission accounting (global connection and
// handshake limits, replay cache, unique-IP sets), readiness and stop
// coordination; none of it is touched per relayed packet.
//
// request_stop() may be called from any thread and wakes every reactor through
// its eventfd. The process is expected to block SIGINT/SIGTERM before creating
// any thread (the leader does this before constructing the runtime). When those
// signals are blocked, reactor 0 installs a signalfd and stops all reactors
// gracefully. When they are not blocked, no signalfd is installed and the
// caller must invoke request_stop() from a signal-aware thread instead.
//
// The referenced Config, UserStore, Statistics, MetadataProvider and
// RevisionBarrier must outlive the Runtime. The runtime never owns them.
//
// Relay fallback is
// limited to an optional fixed raw-TLS masking backend (any IP or hostname,
// e.g. a real web site such as github.com) selected only for
// invalid/unauthenticated initial ClientHello input before any ServerHello
// is emitted; replay/user-cap/saturation failures close and never fall back.
// Authenticated clients are served only through a pooled ME connection carrying
// the mandatory ad-tag unless Direct fallback is explicitly configured.
#pragma once

#include <cstdint>
#include <functional>
#include <memory>
#include <vector>

namespace mtdd {

struct Config;
class MetadataProvider;
class RevisionBarrier;

namespace control {
class Statistics;
class UserStore;
} // namespace control

class Runtime final {
public:
    Runtime(const Config& config, control::UserStore& users,
            control::Statistics& statistics, MetadataProvider& metadata,
            RevisionBarrier& barrier);

    /// @warning If run() has started, the destructor requests stop and waits
    /// without a time bound until the reactor actually exits, so that it never
    /// destroys state still in use. Callers that need a hard time bound must
    /// join run() themselves and treat a stuck reactor as a process fault.
    ~Runtime();

    Runtime(const Runtime&) = delete;
    Runtime& operator=(const Runtime&) = delete;
    Runtime(Runtime&&) = delete;
    Runtime& operator=(Runtime&&) = delete;

    /// Runs the reactor until request_stop(), SIGINT/SIGTERM (when blocked by
    /// the process), or a fatal reactor error. Fatal errors are finalized and
    /// rethrown as std::exception; embedders that call run() on another thread
    /// must catch them (otherwise std::thread terminates the process). Call at
    /// most once.
    void run();

    /// Thread-safe and idempotent. Posts the stop request through an eventfd.
    void request_stop() noexcept;

    /// Bound listener port (the actual port when config.proxy_port was 0).
    std::uint16_t port() const noexcept;

    /// Thread-safe. Changes the ME pool scaling limits of every reactor without
    /// touching live connections; reactors apply them within one housekeeping
    /// tick and existing pools converge through normal scaling. Values must be
    /// in the ranges accepted by Config (1..1000000 and 1..24).
    void set_tunables(std::uint32_t me_clients_per_writer, std::uint32_t me_connections_per_dc);

    /// Thread-safe. Media shaping limits in kbit/s (0 = unlimited): per proxy
    /// user across its media (signed DC < 0) connections, and process-wide.
    void set_media_limits(std::uint64_t user_kbps, std::uint64_t total_kbps) noexcept;

    /// Installs a SIGHUP handler (call before run()). It runs on the reactor
    /// that owns the process signals; a throwing hook is ignored.
    void on_reload(std::function<void()> hook);

    /// Number of reactors created from `workers` (auto-detection included).
    std::size_t worker_count() const noexcept;

    // Operations telemetry: TCP admissions and replay rejections per reactor.
    // These prove that SO_REUSEPORT distributes work; both are bounded by the
    // configured worker count and never read on the relay hot path.
    std::vector<std::uint64_t> accepted_clients_per_worker() const;
    std::vector<std::uint64_t> replay_rejections_per_worker() const;

private:
    struct Impl;
    struct RuntimeState;
    std::unique_ptr<RuntimeState> state_;
};

} // namespace mtdd
