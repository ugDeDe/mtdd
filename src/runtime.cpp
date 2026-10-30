#include "runtime/internal.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <sys/eventfd.h>
#include <sys/signalfd.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstring>
#include <exception>
#include <stdexcept>
#include <system_error>
#include <string>
#include <utility>

namespace mtdd {
namespace {

std::runtime_error syscall_error(const char* what) {
    return std::runtime_error(std::string(what) + ": " + std::strerror(errno));
}

bool numeric_loopback(std::string_view host) {
    std::array<std::uint8_t, 16> bytes{};
    in_addr v4{};
    if (::inet_pton(AF_INET, std::string(host).c_str(), &v4) == 1) {
        return (ntohl(v4.s_addr) >> 24) == 127;
    }
    if (::inet_pton(AF_INET6, std::string(host).c_str(), bytes.data()) == 1) {
        return host == "::1" || host == "0:0:0:0:0:0:0:1";
    }
    return false;
}

// Masking relay targets may be any non-wildcard IP or DNS hostname; deep
// validation already happened in Config::parse, this is a direct-construction
// backstop for embedders that build Config by hand.
bool fallback_target_valid(std::string_view host) {
    if (host.empty() || host == "0.0.0.0" || host == "::") return false;
    if (numeric_loopback(host)) return true;
    in_addr v4{};
    in6_addr v6{};
    if (::inet_pton(AF_INET, std::string(host).c_str(), &v4) == 1) return true;
    if (::inet_pton(AF_INET6, std::string(host).c_str(), &v6) == 1) return true;
    if (host.size() > 253 || host.front() == '-' || host.back() == '-' ||
        host.find("..") != std::string_view::npos) {
        return false;
    }
    for (const char c : host) {
        const auto ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                        (c >= '0' && c <= '9') || c == '-' || c == '.';
        if (!ok) return false;
    }
    return true;
}

} // namespace

namespace detail {

ReplayCache::Outcome ReplayCache::insert(const std::array<std::uint8_t, 32>& key,
                                         std::chrono::steady_clock::time_point now) {
    const std::lock_guard lock{mutex_};
    evict_locked(now);
    if (entries_.find(key) != entries_.end()) return Outcome::duplicate;
    if (entries_.size() >= capacity_) return Outcome::saturated;
    entries_.emplace(key, now);
    order_.emplace_back(key, now);
    return Outcome::accepted;
}

void ReplayCache::evict(std::chrono::steady_clock::time_point now) {
    const std::lock_guard lock{mutex_};
    evict_locked(now);
}

void ReplayCache::evict_locked(std::chrono::steady_clock::time_point now) {
    while (!order_.empty() && now - order_.front().second >= kReplayRetention) {
        const auto key = order_.front().first;
        const auto stamp = order_.front().second;
        order_.pop_front();
        const auto found = entries_.find(key);
        if (found != entries_.end() && found->second == stamp) entries_.erase(found);
    }
}

std::size_t ReplayCache::size() const noexcept {
    const std::lock_guard lock{mutex_};
    return entries_.size();
}

bool ReplayCache::empty() const noexcept {
    const std::lock_guard lock{mutex_};
    return entries_.empty();
}

void SharedState::register_wake(int fd) {
    const std::lock_guard lock{wake_mutex};
    wake_fds.push_back(fd);
    if (!stop.load(std::memory_order_relaxed)) return;
    const std::uint64_t one = 1;
    ssize_t written = 0;
    do {
        written = ::write(fd, &one, sizeof(one));
    } while (written < 0 && errno == EINTR);
}

void SharedState::unregister_wake(int fd) noexcept {
    const std::lock_guard lock{wake_mutex};
    const auto found = std::find(wake_fds.begin(), wake_fds.end(), fd);
    if (found != wake_fds.end()) wake_fds.erase(found);
}

void SharedState::stop_all() noexcept {
    if (stop.exchange(true, std::memory_order_relaxed)) return;
    const std::lock_guard lock{wake_mutex};
    const std::uint64_t one = 1;
    for (const int fd : wake_fds) {
        ssize_t written = 0;
        do {
            written = ::write(fd, &one, sizeof(one));
        } while (written < 0 && errno == EINTR);
    }
}

namespace {
// Per-reactor fatal-injection slots. Relaxed atomics: the flag is consumed once
// by the owning reactor thread and never orders any other state.
std::array<std::atomic<bool>, kMaxWorkers> g_reactor_fatal{};
} // namespace

void set_reactor_fatal_for_test(int worker_index) {
    if (worker_index < 0 ||
        static_cast<std::size_t>(worker_index) >= kMaxWorkers) {
        return;
    }
    g_reactor_fatal[static_cast<std::size_t>(worker_index)].store(
        true, std::memory_order_relaxed);
}

bool consume_reactor_fatal_for_test(std::size_t worker_index) noexcept {
    if (worker_index >= kMaxWorkers) return false;
    return g_reactor_fatal[worker_index].exchange(false, std::memory_order_relaxed);
}

void clear_reactor_fatal_for_test() noexcept {
    for (auto& slot : g_reactor_fatal) slot.store(false, std::memory_order_relaxed);
}

} // namespace detail

Runtime::Impl::Impl(const Config& config, control::UserStore& users,
                    control::Statistics& statistics, MetadataProvider& metadata,
                    RevisionBarrier& barrier,
                    std::shared_ptr<detail::SharedState> shared,
                    std::size_t worker_index, bool reuse_port,
                    bool signal_owner)
    : config_(config), ping_tuning_(detail::me_ping_tuning()), users_(users),
      stats_(statistics), metadata_(metadata), barrier_(barrier),
      shared_(shared ? std::move(shared)
                     : std::make_shared<detail::SharedState>(
                           1, config.global_buffer_bytes)),
      worker_index_(worker_index), reuse_port_(reuse_port),
      signal_owner_(signal_owner), random_(protocol::buffered_random()) {
    if (config_.max_frame_bytes == 0 || config_.connection_queue_bytes == 0) {
        throw std::invalid_argument("runtime configuration has zero limits");
    }
    if (std::all_of(config_.ad_tag.begin(), config_.ad_tag.end(),
                    [](std::uint8_t byte) { return byte == 0; })) {
        throw std::invalid_argument("runtime requires a non-zero 16-byte ad tag");
    }
    if (config_.handshake_timeout.count() <= 0 || config_.shutdown_timeout.count() <= 0) {
        throw std::invalid_argument("runtime timeouts must be positive");
    }
    if (config_.me_connections_per_dc < 1 || config_.me_connections_per_dc > 24) {
        throw std::invalid_argument("me_connections_per_dc must be in 1..24");
    }
    if (config_.me_clients_per_writer == 0 || config_.me_clients_per_writer > 1000000) {
        throw std::invalid_argument("me_clients_per_writer must be in 1..1000000");
    }
    if (config_.fallback_port != 0) {
        if (!fallback_target_valid(config_.fallback_host)) {
            throw std::invalid_argument("fallback_host must be an IP address or a DNS hostname");
        }
        if (config_.fallback_port == config_.proxy_port ||
            config_.fallback_port == config_.control_port) {
            throw std::invalid_argument("fallback_port must differ from proxy/control ports");
        }
    }
    // The freelist is per reactor, so bound it by the per-worker share of the
    // process-wide cap: 256 reactors must not retain 256 * 8192 objects.
    const auto pool_budget =
        std::max<std::size_t>(64, detail::kMaxPooledClients / shared_->workers);
    client_pool_limit_ = config_.max_connections == 0
                             ? pool_budget
                             : std::min<std::size_t>(config_.max_connections,
                                                     pool_budget);
    stats_.set_unique_ip_min_bytes(config_.unique_ip_min_bytes);
    setup();
}

Runtime::Impl::~Impl() {
    request_stop();
    if (started_.load(std::memory_order_relaxed)) {
        // R3: never finalize/destroy Impl while run() is still using it. The
        // wait is intentionally unbounded: if the reactor is blocked in an
        // unbounded dependency call, memory safety wins over a time bound.
        // Callers should normally join run() first; the public header documents
        // this synchronization contract.
        std::unique_lock lock{exit_mutex_};
        exit_changed_.wait(lock, [this] { return exited_; });
    }
    if (!finalized_) finalize();
    // Backstop: finalize() releases the pool, but if it threw midway the
    // recycled objects must still be freed here.
    release_client_pool();
    // The eventfd is about to be closed; drop it from the process-wide stop
    // list so a later stop_all() cannot write to a closed/reused descriptor.
    if (wake_.valid()) shared_->unregister_wake(wake_.get());
}

void Runtime::Impl::setup() {
    epoll_.reset(::epoll_create1(EPOLL_CLOEXEC));
    if (!epoll_) throw syscall_error("epoll_create1");

    wake_.reset(::eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC));
    if (!wake_) throw syscall_error("eventfd");
    shared_->register_wake(wake_.get());

    const int backlog = config_.max_connections == 0
                            ? 4096
                            : static_cast<int>(
                                  std::min<std::uint32_t>(config_.max_connections, 4096));
    auto listener = io::listen_tcp(config_.proxy_host, config_.proxy_port, backlog, reuse_port_);
    if (!listener.ok()) {
        errno = listener.error;
        throw syscall_error("cannot bind proxy listener");
    }
    listener_ = std::move(listener.fd);
    // Accepted sockets inherit these from the listener (Linux copies the
    // listening socket's options on accept), so the accept path issues no
    // per-connection setsockopt. Small FakeTLS records: no Nagle. Keepalive and
    // TCP_USER_TIMEOUT find vanished peers instead of idle_timeout.
    (void)io::set_tcp_nodelay(listener_.get());
    if (config_.client_keepalive.count() > 0) {
        const int idle = static_cast<int>(config_.client_keepalive.count());
        (void)io::set_tcp_keepalive(listener_.get(), idle, std::clamp(idle / 4, 5, 30), 4);
    }
    if (config_.client_ack_timeout.count() > 0) {
        (void)io::set_tcp_user_timeout(
            listener_.get(), static_cast<unsigned>(config_.client_ack_timeout.count()) * 1000U);
    }

    const auto local = io::local_endpoint(listener_.get());
    if (!local) throw std::runtime_error("cannot read bound proxy port");
    port_public_.store(local->port, std::memory_order_relaxed);

    // Fixed reactor tokens: listener, wake and (optionally) signal.
    auto add_fixed = [this](Kind kind, int fd, std::uint32_t events, std::uint32_t& armed,
                            std::uint64_t& token_out) {
        token_out = add_target(Target{kind, nullptr});
        epoll_event event{};
        event.events = events;
        event.data.u64 = token_out;
        if (::epoll_ctl(epoll_.get(), EPOLL_CTL_ADD, fd, &event) != 0) {
            throw syscall_error("epoll_ctl add");
        }
        armed = events;
    };
    add_fixed(Kind::listener, listener_.get(), EPOLLIN, listener_events_, listener_token_);
    add_fixed(Kind::wake, wake_.get(), EPOLLIN, wake_events_, wake_token_);

    // signalfd only works for signals that are actually blocked by the process.
    // The leader blocks SIGINT/SIGTERM before creating threads. When a test or a
    // different embedder does not, we deliberately do not install a handler and
    // the caller uses request_stop() instead (documented limitation).
    sigset_t all{};
    sigemptyset(&all);
    sigaddset(&all, SIGINT);
    sigaddset(&all, SIGTERM);
    sigset_t current{};
    // SIGHUP (reload) is taken only when the embedder blocked it as well;
    // otherwise its default action is left to the process.
    sigset_t blocked{};
    if (::pthread_sigmask(SIG_SETMASK, nullptr, &blocked) == 0 &&
        sigismember(&blocked, SIGHUP) == 1) {
        sigaddset(&all, SIGHUP);
    }
    if (signal_owner_ && ::pthread_sigmask(SIG_SETMASK, nullptr, &current) == 0 &&
        (sigismember(&current, SIGINT) == 1 || sigismember(&current, SIGTERM) == 1)) {
        const int fd = ::signalfd(-1, &all, SFD_NONBLOCK | SFD_CLOEXEC);
        if (fd >= 0) {
            signal_.reset(fd);
            add_fixed(Kind::signal, signal_.get(), EPOLLIN, signal_events_, signal_token_);
            signal_registered_ = true;
        }
    }

    read_buffer_.resize(detail::kReadBatch);
    next_eof_sweep_ = Clock::now();
    next_eof_deadline_ = Time::max();
    reaccount_shared();
}

void Runtime::Impl::run() {
    if (started_.exchange(true, std::memory_order_relaxed)) return;
    std::exception_ptr fatal;
    try {
        Time now = Clock::now();
        poll_users(now);
        poll_metadata(now);
        reaccount_shared();
        recompute_ready();
        next_poll_ = now + detail::kPollInterval;
        next_gauge_ = now + std::chrono::seconds(1);
        // Publish one initial worker sample so a reactor that stalls before its
        // first 1 Hz tick still has a heartbeat that snapshot() can age out.
        stats_.set_worker_diagnostics(worker_index_, budget_used_,
                                      config_.global_buffer_bytes,
                                      clients_.size(), handshake_count_);
        stats_.set_worker_heartbeat(worker_index_);
        stats_.set_worker_housekeeping_lateness(worker_index_, 0, 0);

        std::array<epoll_event, detail::kEpollBatch> events{};
        while (true) {
            now = Clock::now();
            if (exit_requested() && !stopping_) begin_shutdown(now);
            if (stopping_) {
                shutdown_pump(now);
                if (clients_.empty()) break;
                if (now >= shutdown_deadline_) break;
            }
            if (now >= next_poll_) {
                // Record how late the fixed 150 ms housekeeping tick actually
                // ran. A late tick with a fresh heartbeat separates event-loop
                // blocking from budget gating; a stale heartbeat separates a
                // stopped reactor.
                const auto late = now > next_poll_
                                      ? std::chrono::duration_cast<
                                            std::chrono::milliseconds>(
                                            now - next_poll_)
                                            .count()
                                      : 0;
                housekeeping_lateness_ms_ =
                    static_cast<std::uint64_t>(late > 0 ? late : 0);
                housekeeping_lateness_max_ms_ =
                    std::max(housekeeping_lateness_max_ms_,
                             housekeeping_lateness_ms_);
                poll_users(now);
                poll_metadata(now);
                housekeeping(now);
                // Test seam: a synthetic fatal error leaves the loop like any
                // other exception, so finalize() runs and run() rethrows.
                if (detail::consume_reactor_fatal_for_test(worker_index_)) {
                    throw std::runtime_error("injected reactor failure (test seam)");
                }
                next_poll_ = now + detail::kPollInterval;
            }
            if (now >= next_gauge_) {
                reaccount_shared();
                unpause_clients_if_possible(now);
                // Buffer/replay gauges are refreshed at 1 Hz, not per packet.
                stats_.set_replay_cache_entries(worker_index_, shared_->replay.size());
                std::uint64_t queued = 0;
                std::uint64_t pending_write = 0;
                std::uint64_t relay = 0;
                std::uint64_t me_pending = 0;
                std::map<std::int16_t, std::uint64_t> direct_active;
                for (auto& [token, client] : clients_) {
                    (void)token;
                    if (now - client->last_activity >= detail::kIdleTrimAfter) {
                        trim_idle_client(*client);
                    }
                    queued += client->s2c_wire.size() + client->c2s_capacity;
                    if (client->c2b) queued += client->c2b->bytes();
                    if (client->out) pending_write += client->out->bytes();
                    if (client->tls) relay += client->tls->retained_bytes();
                    if (client->decoder) relay += client->decoder->retained_bytes();
                    if (client->direct_out) {
                        // Direct keeps its client->DC backlog here; include it in
                        // the diagnostic gauges or an exhausted budget looks idle.
                        queued += client->direct_out->bytes();
                        pending_write += client->direct_out->bytes();
                    }
                    if (client->route == Client::Route::direct) {
                        ++direct_active[client->route_dc];
                    }
                }
                for (const auto& [dc, pool] : me_pool_) {
                    for (const auto& me : pool.conns) {
                        if (!me) continue;
                        queued += me->frame_bytes;
                        if (me->out) {
                            pending_write += me->out->bytes();
                            me_pending += me->out->bytes();
                        }
                        if (me->session) relay += me->session->retained_bytes();
                        me_pending += me->frame_bytes;
                        publish_me_queue(*me);
                    }
                    // Per-DC socket bytes are base + live members; snapshot()
                    // adds the reactors together.
                    publish_me_io(dc);
                    // Pool gauges, readiness and keepalive are reactor-owned
                    // per-DC aggregates (see publish_me_pool).
                    publish_me_pool(dc);
                    // The same 1 Hz pool traversal also publishes the
                    // per-worker budget/read diagnostics; no extra client scan.
                    publish_me_worker_diagnostics(dc, now);
                    // Publishes the age of the newest answer of a live member,
                    // or an explicit "no answer" when no live member has one.
                    publish_me_answer_age(dc, now);
                }
                // Direct counters use the same bounded signed-DC labels. All
                // configured Direct DCs are published even before their first
                // connection, so a connect failure is observable.
                std::vector<std::int16_t> direct_dcs = config_.direct_fallback_dcs;
                for (const auto& [dc, ignored] : direct_accepted_) {
                    (void)ignored;
                    if (std::find(direct_dcs.begin(), direct_dcs.end(), dc) == direct_dcs.end()) {
                        direct_dcs.push_back(dc);
                    }
                }
                for (const std::int16_t dc : direct_dcs) {
                    const auto active = direct_active.find(dc);
                    const auto accepted = direct_accepted_.find(dc);
                    const auto failed = direct_connect_fail_.find(dc);
                    const auto rx = direct_rx_bytes_.find(dc);
                    const auto tx = direct_tx_bytes_.find(dc);
                    stats_.me_direct(worker_index_, dc,
                                     active == direct_active.end() ? 0 : active->second,
                                     accepted == direct_accepted_.end() ? 0 : accepted->second,
                                     failed == direct_connect_fail_.end() ? 0 : failed->second,
                                     rx == direct_rx_bytes_.end() ? 0 : rx->second,
                                     tx == direct_tx_bytes_.end() ? 0 : tx->second);
                }
                stats_.set_buffer_bytes(worker_index_, control::BufferState::queued, queued);
                stats_.set_buffer_bytes(worker_index_, control::BufferState::pending_write,
                                        pending_write);
                stats_.set_buffer_bytes(worker_index_, control::BufferState::relay, relay);
                stats_.me_pending_buffer_bytes(worker_index_, me_pending);
                stats_.set_buffer_budget_used(worker_index_, budget_used_);
                stats_.set_handshakes_pending(worker_index_, handshake_count_);
                // Per-worker truth: the summed budget gauge above can hide one
                // reactor at its local partition limit. The heartbeat is a
                // monotonic stamp; snapshot() derives its age independently.
                stats_.set_worker_diagnostics(
                    worker_index_, budget_used_, config_.global_buffer_bytes,
                    clients_.size(), handshake_count_);
                stats_.set_worker_heartbeat(worker_index_);
                stats_.set_worker_housekeeping_lateness(
                    worker_index_, housekeeping_lateness_ms_,
                    housekeeping_lateness_max_ms_);
                const auto& lifecycle = detail::client_lifecycle_telemetry();
                stats_.set_client_pool(
                    worker_index_, free_clients_.size(),
                    lifecycle.allocations.load(std::memory_order_relaxed),
                    lifecycle.reuses.load(std::memory_order_relaxed));
                next_gauge_ = now + std::chrono::seconds(1);
                // Expiry and quota are time/traffic driven, not snapshot driven.
                sweep_user_policy(now);
            }

            const int timeout = wait_timeout_ms(now);
            const int count = ::epoll_wait(epoll_.get(), events.data(),
                                           static_cast<int>(events.size()), timeout);
            if (count < 0) {
                const int error = errno;
                if (error == EINTR) continue;
                throw std::system_error(error, std::generic_category(), "epoll_wait");
            }
            now = Clock::now();
            for (int i = 0; i < count; ++i) {
                const std::uint64_t token = events[static_cast<std::size_t>(i)].data.u64;
                const auto found = targets_.find(token);
                if (found == targets_.end()) continue;
                const Target target = found->second;
                try {
                    handle_event(target, events[static_cast<std::size_t>(i)].events, now);
                } catch (const std::exception&) {
                    // close_client()/fail_me() allocate (ME close frame). A
                    // throw here must not escape and turn one bad event into a
                    // fatal process shutdown.
                    try {
                        if (target.kind == Kind::client) {
                            close_client(token);
                        } else if (target.kind == Kind::direct_backend) {
                            // The Direct target token is not the client token.
                            const auto owner_client = clients_.find(target.owner);
                            if (owner_client != clients_.end()) close_client(owner_client->first);
                        } else if (target.kind == Kind::me && target.object != nullptr) {
                            fail_me(*static_cast<MeConn*>(target.object), now);
                        }
                    } catch (...) {
                    }
                } catch (...) {
                    try {
                        if (target.kind == Kind::client) close_client(token);
                        if (target.kind == Kind::direct_backend) {
                            const auto owner_client = clients_.find(target.owner);
                            if (owner_client != clients_.end()) close_client(owner_client->first);
                        }
                    } catch (...) {
                    }
                }
            }
            process_deferred();
            process_deadlines(Clock::now());
            if (!rate_clients_.empty()) process_rate_resumes(Clock::now());
            // O(eof/fin clients) work after the batch, not a full client scan.
            // This makes a drained EOF close prompt instead of waiting for the
            // 150 ms housekeeping tick.
            const Time finished = Clock::now();
            media_release(finished);
            finish_eof_clients(finished);
            // Fallback pairs are pumped by their own read/write events; the
            // sweep only closes finished or expired pairs, so it runs from the
            // 150 ms housekeeping tick instead of after every epoll batch.
        }
    } catch (...) {
        fatal = std::current_exception();
    }
    // Finalization must run on every path, including fatal errors, so that
    // clients/counters/barrier reach a consistent terminal state.
    try {
        finalize();
    } catch (...) {
        if (!fatal) fatal = std::current_exception();
        mark_exited();
    }
    if (fatal) std::rethrow_exception(fatal);
}

void Runtime::Impl::request_stop() noexcept {
    stop_requested_.store(true, std::memory_order_relaxed);
    // Wakes every reactor, not just this one. Idempotent.
    shared_->stop_all();
}

std::uint64_t Runtime::Impl::add_target(const Target& target) {
    const std::uint64_t token = next_token_++;
    targets_.emplace(token, target);
    return token;
}

Runtime::Impl::Target* Runtime::Impl::find_target(std::uint64_t token) {
    const auto found = targets_.find(token);
    return found == targets_.end() ? nullptr : &found->second;
}

void Runtime::Impl::remove_target(std::uint64_t token) { targets_.erase(token); }

void Runtime::Impl::set_interest(std::uint64_t token, int fd, std::uint32_t& armed,
                                 std::uint32_t desired) {
    if (desired == armed) return;
    epoll_event event{};
    event.events = desired;
    event.data.u64 = token;
    int operation = EPOLL_CTL_MOD;
    if (desired == 0) {
        operation = EPOLL_CTL_DEL;
    } else if (armed == 0) {
        operation = EPOLL_CTL_ADD;
    }
    if (::epoll_ctl(epoll_.get(), operation, fd, &event) == 0 || desired == 0) {
        armed = desired;
    }
}

void Runtime::Impl::update_client_interest(Client& client) {
    if (client.token == 0) return;
    if (client.phase == Client::Phase::fallback) {
        update_fallback_client_interest(client);
        return;
    }
    std::uint32_t desired = 0;
    // EPOLLRDHUP is level-triggered. Once the FIN bit has been observed (or EOF
    // has been reached), keep it out of the interest set or the reactor spins.
    if (!client.fin_pending && !client.read_eof) desired |= EPOLLRDHUP;
    // EPOLLIN stays armed until recv()==0. A pending FIN alone must NOT stop
    // reading: bytes may still be queued behind the FIN. Budget pause disables
    // it temporarily; the unpause path re-arms it so the tail is preserved.
    // A throttled media client whose held requests reached the queue size is
    // not read further, so shaping never turns into a queue-overflow close.
    const bool media_hold = client.media_throttled &&
                            client.c2s_capacity >= config_.connection_queue_bytes;
    // A rate-limited direction stops reading its source. On the ME route the
    // shared ME socket cannot be paused per user, so a drained s2c bucket
    // throttles the requests that drive downloads (c2s) instead.
    const bool rate_paused =
        client.rate_pause_c2s ||
        (client.rate_pause_s2c && client.route != Client::Route::direct);
    if (!client.read_eof && !client.draining && !client.budget_paused &&
        !client.close_requested && !media_hold && !rate_paused) {
        desired |= EPOLLIN;
    }
    if (client_wants_write(client)) desired |= EPOLLOUT;
    set_interest(client.token, client.fd.get(), client.armed, desired);
}

void Runtime::Impl::update_me_interest(MeConn& me) {
    if (!me.fd.valid()) {
        if (me.armed != 0) {
            // The descriptor is already closed; the reactor token is removed
            // separately, so there is nothing to deregister here.
            me.armed = 0;
        }
        return;
    }
    std::uint32_t desired = 0;
    if (me.state == MeConn::State::connecting) {
        desired |= EPOLLRDHUP | EPOLLOUT;
    } else {
        // While the relay budget refused a read, neither unread data nor a
        // level-triggered FIN bit may keep the reactor spinning. The 150 ms
        // housekeeping tick retries the unpause and re-arms the mask.
        if (!me.budget_paused) desired |= EPOLLIN | EPOLLRDHUP;
        if ((me.out && !me.out->empty()) || !me.frames.empty()) desired |= EPOLLOUT;
    }
    set_interest(me.token, me.fd.get(), me.armed, desired);
}

void Runtime::Impl::update_listener_interest() {
    // Keep EPOLLIN off while the buffer budget cannot admit a client; otherwise
    // the reactor accepts sockets only to close them. Housekeeping re-evaluates
    // this every tick, so acceptance resumes once the budget drains.
    const bool accept = !stopping_ && listener_.valid() &&
        budget_allows(detail::kBudgetHeadroom + 8192) &&
        (config_.max_connections == 0 ||
         (clients_.size() < static_cast<std::size_t>(config_.max_connections) &&
          shared_->connections.load(std::memory_order_relaxed) <
              config_.max_connections));
    const std::uint32_t desired = accept ? EPOLLIN : std::uint32_t{0};
    if (listener_.valid()) {
        set_interest(listener_token_, listener_.get(), listener_events_, desired);
    }
}

int Runtime::Impl::wait_timeout_ms(Time now) const {
    Time limit = now + std::chrono::milliseconds(250);
    if (next_poll_ < limit) limit = next_poll_;
    if (next_gauge_ < limit) limit = next_gauge_;
    if (const auto deadline = deadlines_.next(); deadline && *deadline < limit) limit = *deadline;
    // Wake for the earliest FIN/read-EOF expiry even when no traffic arrives.
    // The sweep never runs before next_eof_sweep_, so waking earlier is wasted.
    if (next_eof_deadline_ != Time::max()) {
        const Time eof_wake = std::max(next_eof_deadline_, next_eof_sweep_);
        if (eof_wake < limit) limit = eof_wake;
    }
    if (!media_throttled_.empty() && next_media_check_ < limit) limit = next_media_check_;
    if (next_rate_resume_ < limit) limit = next_rate_resume_;
    if (stopping_ && shutdown_deadline_ < limit) limit = shutdown_deadline_;
    if (limit <= now) return 0;
    // Round a positive sub-millisecond delay up: truncating it to 0 would turn
    // epoll_wait into a busy poll until the deadline.
    const auto remaining = std::chrono::ceil<std::chrono::milliseconds>(limit - now);
    const auto count = std::max<std::int64_t>(remaining.count(), 1);
    return static_cast<int>(std::min<std::int64_t>(count, 250));
}

void Runtime::Impl::handle_event(const Target& target, std::uint32_t events, Time now) {
    switch (target.kind) {
    case Kind::listener:
        if ((events & EPOLLIN) != 0) accept_clients(now);
        break;
    case Kind::wake: {
        std::uint64_t value = 0;
        ssize_t read = 0;
        do {
            read = ::read(wake_.get(), &value, sizeof(value));
        } while (read < 0 && errno == EINTR);
        (void)read;
        // A process signal is global: the signal-owning reactor must stop all
        // peers, not only itself.
        request_stop();
        begin_shutdown(now);
        break;
    }
    case Kind::signal: {
        signalfd_siginfo info{};
        ssize_t read = 0;
        do {
            read = ::read(signal_.get(), &info, sizeof(info));
        } while (read < 0 && errno == EINTR);
        if (read == static_cast<ssize_t>(sizeof(info)) && info.ssi_signo == SIGHUP) {
            // Reload: apply live tunables, keep every connection.
            if (shared_->reload_hook) {
                try {
                    shared_->reload_hook();
                } catch (...) {
                }
            }
            break;
        }
        // A process signal is global: the signal-owning reactor must stop all
        // peers, not only itself.
        request_stop();
        begin_shutdown(now);
        break;
    }
    case Kind::client: {
        auto* client = static_cast<Client*>(target.object);
        if (client == nullptr) break;
        auto found = clients_.find(client->token);
        if (found == clients_.end() || found->second.get() != client) break;
        handle_client(*client, events, now);
        break;
    }
    case Kind::me: {
        auto* me = static_cast<MeConn*>(target.object);
        if (me == nullptr) break;
        handle_me(*me, events, now);
        break;
    }
    case Kind::me_ping:
        // Deadline-only token: it is never registered with epoll.
        break;
    case Kind::direct_backend: {
        const auto found = clients_.find(target.owner);
        if (found == clients_.end()) break;
        Client& client = *found->second;
        if (client.route != Client::Route::direct) break;
        handle_direct_backend(client, events, now);
        break;
    }
    case Kind::fallback_backend: {
        const auto found = clients_.find(target.owner);
        if (found == clients_.end()) break;
        Client& client = *found->second;
        // The target table is authoritative for this backend registration; it
        // is removed on close, so no stale pointer/token can reach this branch.
        if (!client.backend.valid()) break;
        handle_fallback_backend(client, events, now);
        break;
    }
    }
}

void Runtime::Impl::process_deadlines(Time now) {
    auto due = deadlines_.due(now, 256);
    for (const std::uint64_t token : due) {
        const auto target = targets_.find(token);
        if (target == targets_.end()) continue;
        // Copy before dispatch: the handler may erase targets_[token].
        const Kind kind = target->second.kind;
        void* const object = target->second.object;
        const std::uint64_t owner = target->second.owner;
        try {
            if (kind == Kind::client) {
                auto found = clients_.find(token);
                if (found != clients_.end()) on_client_deadline(*found->second, now);
            } else if (kind == Kind::me && object != nullptr) {
                auto& me = *static_cast<MeConn*>(object);
                if (me.state == MeConn::State::backoff) {
                    if (!stopping_ && !me.draining) connect_me(me, now);
                } else if (me.state == MeConn::State::connecting ||
                           me.state == MeConn::State::handshaking) {
                    stats_.me_request(worker_index_, me.dc, control::MeResult::timeout);
                    fail_me(me, now);
                } else if (me.state == MeConn::State::ready) {
                    // Bounded self-wake for a ready queue that still has work
                    // but no readiness event left to fire.
                    pump_me_ready_queue(me, now);
                }
            } else if (kind == Kind::me_ping && object != nullptr) {
                on_me_ping_deadline(*static_cast<MeConn*>(object), now);
            } else if (kind == Kind::direct_backend) {
                const auto found = clients_.find(owner);
                if (found == clients_.end()) continue;
                Client& client = *found->second;
                if (client.route != Client::Route::direct) continue;
                if (client.direct_connecting) {
                    ++direct_connect_fail_[client.route_dc];
                    close_client(client.token);
                } else if ((client.direct_eof &&
                            now >= client.direct_eof_at + config_.shutdown_timeout) ||
                           (client.direct_fin_pending && !client.direct_eof &&
                            now >= client.direct_fin_at + config_.shutdown_timeout)) {
                    close_client(client.token);
                }
            } else if (kind == Kind::fallback_backend) {
                const auto found = clients_.find(owner);
                if (found == clients_.end()) continue;
                Client& client = *found->second;
                if (client.backend_token == token) on_fallback_deadline(client, now);
            }
        } catch (...) {
            if (kind == Kind::client) close_client(token);
        }
    }
}

} // namespace mtdd
