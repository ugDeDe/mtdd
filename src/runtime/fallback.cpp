// Masking relay target selection (automatic SNI fronting), in priority
// order:
//   1. Explicitly configured destination (fallback_host/fallback_port) —
//      byte relay there, preserving the historical behavior for deployments
//      that pin a fixed backend.
//   2. Otherwise: a probe whose SNI matches a configured FakeTLS domain (or
//      a subdomain of it) is relayed to the real server of that configured
//      name on 443, so active probes receive a genuine certificate for the
//      covered name; any other probe goes to the global tls_domain.
//   3. Otherwise the probe is closed.
// This is deliberately a byte relay, not a TLS/HTTP implementation.
//
// Target names are resolved only by MaskingResolver's background thread; a
// reactor reads its cache and never calls getaddrinfo.
#include "internal.hpp"

#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <cerrno>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <optional>
#include <span>
#include <utility>
#include <vector>

namespace mtdd {

namespace {

std::string to_lower(std::string_view text) {
    std::string out(text);
    for (auto& c : out) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return out;
}

bool sni_domain_matches(std::string_view sni, std::string_view domain) {
    auto name = to_lower(sni);
    auto covered = to_lower(domain);
    if (!name.empty() && name.back() == '.') name.pop_back();
    if (!covered.empty() && covered.back() == '.') covered.pop_back();
    if (covered.empty()) return false;
    return name == covered ||
           (name.size() > covered.size() &&
            name.compare(name.size() - covered.size() - 1, covered.size() + 1,
                         "." + covered) == 0);
}

}  // namespace

namespace {
std::mutex g_masking_override_mutex;
std::optional<detail::DirectEndpointOverride> g_masking_override;

std::optional<detail::DirectEndpointOverride> masking_override() {
    std::lock_guard<std::mutex> lock(g_masking_override_mutex);
    return g_masking_override;
}
std::optional<detail::MaskingResolveHooks> g_masking_hooks;

std::optional<detail::MaskingResolveHooks> masking_hooks() {
    std::lock_guard<std::mutex> lock(g_masking_override_mutex);
    return g_masking_hooks;
}
}  // namespace

namespace detail {
void set_masking_endpoint_override(std::optional<DirectEndpointOverride> value) {
    std::lock_guard<std::mutex> lock(g_masking_override_mutex);
    g_masking_override = std::move(value);
}

void set_masking_resolve_hooks_for_test(std::optional<MaskingResolveHooks> hooks) {
    std::lock_guard<std::mutex> lock(g_masking_override_mutex);
    g_masking_hooks = std::move(hooks);
}

namespace {
// Cache key: DNS names compare case-insensitively, a trailing dot is noise.
std::string dns_key(std::string_view name) {
    auto key = to_lower(name);
    if (!key.empty() && key.back() == '.') key.pop_back();
    return key;
}

// Uniform in [0, span): spreads probes so restarts and refreshes do not form
// a fixed schedule towards the real server.
std::chrono::milliseconds random_below(std::chrono::milliseconds span) {
    if (span.count() <= 0) return {};
    std::array<std::uint8_t, 4> draw{};
    protocol::system_random()(draw);
    const std::uint32_t value = (static_cast<std::uint32_t>(draw[0]) << 24) |
                                (static_cast<std::uint32_t>(draw[1]) << 16) |
                                (static_cast<std::uint32_t>(draw[2]) << 8) | draw[3];
    return std::chrono::milliseconds(static_cast<std::int64_t>(
        value % static_cast<std::uint64_t>(span.count())));
}
}  // namespace

MaskingResolver::MaskingResolver(const Config& config, control::UserStore& users)
    : users_(users),
      tls_domain_(config.tls_domain),
      fallback_host_(config.fallback_host),
      fallback_port_(config.fallback_port),
      masking_(config.masking) {
    const auto hooks = masking_hooks();
    if (hooks && hooks->port != 0) probe_port_ = hooks->port;
    if (hooks) probe_delay_ = hooks->probe_delay;
    if (hooks && hooks->resolve) {
        resolve_ = hooks->resolve;
        refresh_ = hooks->refresh;
    } else {
        resolve_ = [](const std::string& name) { return io::resolve_numeric_host(name); };
    }
    retry_min_ = std::min<std::chrono::milliseconds>(kMaskingResolveRetryMin, refresh_);
}

MaskingResolver::~MaskingResolver() { stop(); }

bool MaskingResolver::needed() const {
    if (fallback_port_ != 0) return !io::is_numeric_address(fallback_host_);
    return masking_ && !tls_domain_.empty();
}

void MaskingResolver::start() {
    if (thread_.joinable() || !needed()) return;
    thread_ = std::thread([this] { run(); });
}

void MaskingResolver::stop() noexcept {
    {
        const std::lock_guard lock{mutex_};
        stop_ = true;
    }
    cancel_.store(true);
    wake_.notify_all();
    // Bounded by the one lookup the thread may be inside.
    if (thread_.joinable()) {
        try {
            thread_.join();
        } catch (...) {
        }
    }
}

std::string MaskingResolver::address(std::string_view host) {
    const auto key = dns_key(host);
    {
        const std::lock_guard lock{mutex_};
        const auto found = entries_.find(key);
        if (found != entries_.end() && !found->second.address.empty()) {
            return found->second.address;
        }
        kicked_ = true;
    }
    // A wake-up only: the thread re-reads the configured names (a personal
    // domain may have just been added) and still honours each name's backoff,
    // so a probe flood cannot become a DNS flood.
    wake_.notify_one();
    return {};
}

std::optional<MaskingResolver::ServerFlight> MaskingResolver::server_flight(
    std::string_view domain) {
    const auto key = dns_key(domain);
    const std::lock_guard lock{mutex_};
    const auto found = probes_.find(key);
    if (found == probes_.end()) return std::nullopt;
    return found->second.flight;
}

std::optional<MaskingResolver::ServerFlight> MaskingResolver::probe_flight(
    const std::string& address, std::uint16_t port, const std::string& name) {
    ServerFlight flight{protocol::kServerFlightMax, 0};
    for (std::size_t i = 0; i < kServerFlightSamples; ++i) {
        const auto sample = measure_server_flight(address, port, name, kServerFlightProbeTimeout,
                                                  [this] { return cancel_.load(); });
        if (!sample) return std::nullopt;
        flight.min = std::min(flight.min, *sample);
        flight.max = std::max(flight.max, *sample);
    }
    return flight;
}

void MaskingResolver::run_probe(std::unique_lock<std::mutex>& lock, const std::string& name) {
    // The address the masking relay dials for this name: the test override,
    // else the cached DNS answer. Never resolved here.
    std::string address;
    std::uint16_t port = probe_port_;
    if (const auto override_target = masking_override()) {
        address = override_target->host;
        port = override_target->port;
    } else if (const auto entry = entries_.find(name); entry != entries_.end()) {
        address = entry->second.address;
    }
    if (address.empty()) {
        // Unresolved yet: the DNS entry goes first; look again shortly.
        probes_.at(name).next_attempt = Clock::now() + kMaskingResolvePoll;
        return;
    }
    lock.unlock();
    std::optional<ServerFlight> flight;
    try {
        flight = probe_flight(address, port, name);
    } catch (...) {
    }
    lock.lock();
    const auto found = probes_.find(name);
    if (found == probes_.end()) return;  // evicted meanwhile
    auto& probe = found->second;
    const auto now = Clock::now();
    if (flight) {
        probe.flight = flight;
        probe.backoff = {};
        probe.next_attempt = now + kServerFlightRefresh + random_below(kServerFlightProbeJitter);
    } else {
        // The last good measurement (if any) stays in use meanwhile.
        probe.backoff = probe.backoff.count() == 0
                            ? std::chrono::milliseconds(kServerFlightRetryMin)
                            : std::min<std::chrono::milliseconds>(probe.backoff * 2,
                                                                  kServerFlightRetryMax);
        probe.next_attempt = now + probe.backoff;
    }
}

std::optional<MaskingResolver::Names> MaskingResolver::configured_names() {
    const bool overridden = masking_override().has_value();
    std::shared_ptr<const control::UserSnapshot> snapshot;
    if (fallback_port_ == 0 && masking_) snapshot = users_.snapshot();
    if (names_valid_ && snapshot == names_snapshot_ && overridden == names_overridden_) {
        return std::nullopt;
    }
    Names names;
    const auto add = [](std::vector<std::string>& list, std::string_view name) {
        if (name.empty() || io::is_numeric_address(name)) return;
        auto key = dns_key(name);
        if (std::find(list.begin(), list.end(), key) == list.end()) {
            list.push_back(std::move(key));
        }
    };
    if (fallback_port_ != 0) {
        add(names.resolve, fallback_host_);
    } else if (masking_ && !tls_domain_.empty()) {
        // Every automatically masked domain is also probed for its flight.
        add(names.probe, tls_domain_);
        if (snapshot) {
            for (const auto& user : snapshot->users) add(names.probe, user.policy.tls_domain);
        }
        // The test endpoint override replaces every automatic target, so
        // nothing needs resolving while it is installed.
        if (!overridden) names.resolve = names.probe;
    }
    names_snapshot_ = std::move(snapshot);
    names_overridden_ = overridden;
    names_valid_ = true;
    return names;
}

void MaskingResolver::run() {
    std::unique_lock lock{mutex_};
    while (!stop_) {
        kicked_ = false;
        lock.unlock();
        std::optional<Names> names;
        try {
            names = configured_names();
        } catch (...) {
            // Allocation failure: keep the current set, retry next wake-up.
        }
        lock.lock();
        if (stop_) break;
        auto now = Clock::now();
        if (names) {
            // Evict names no longer configured; new names are due at once.
            const auto& resolve = names->resolve;
            std::erase_if(entries_, [&resolve](const auto& item) {
                return std::find(resolve.begin(), resolve.end(), item.first) == resolve.end();
            });
            for (const auto& name : resolve) entries_.try_emplace(name, Entry{{}, now, {}});
            // New domains are probed after the startup delay, not at once.
            const auto& probe = names->probe;
            std::erase_if(probes_, [&probe](const auto& item) {
                return std::find(probe.begin(), probe.end(), item.first) == probe.end();
            });
            for (const auto& name : probe) {
                if (probes_.contains(name)) continue;
                const auto delay = probe_delay_ ? *probe_delay_
                                                : kServerFlightProbeDelayMin +
                                                      random_below(kServerFlightProbeJitter);
                probes_.emplace(name, Probe{now + delay, {}, {}});
            }
        }
        std::string due;
        Clock::time_point next = now + kMaskingResolvePoll;
        for (const auto& [name, entry] : entries_) {
            if (entry.next_attempt <= now) {
                due = name;
                break;
            }
            next = std::min(next, entry.next_attempt);
        }
        if (due.empty()) {
            // DNS first; then at most one due server-flight probe.
            std::string probe_due;
            for (const auto& [name, probe] : probes_) {
                if (probe.next_attempt <= now) {
                    probe_due = name;
                    break;
                }
                next = std::min(next, probe.next_attempt);
            }
            if (!probe_due.empty()) {
                run_probe(lock, probe_due);
                continue;
            }
            wake_.wait_until(lock, next, [this] { return stop_ || kicked_; });
            continue;
        }
        // Never hold the lock across the lookup: reactors keep reading the
        // cache (and its stale addresses) meanwhile.
        lock.unlock();
        std::optional<std::string> resolved;
        try {
            resolved = resolve_(due);
        } catch (...) {
        }
        lock.lock();
        now = Clock::now();
        const auto found = entries_.find(due);
        if (found == entries_.end()) continue;  // evicted meanwhile
        auto& entry = found->second;
        if (resolved && !resolved->empty()) {
            entry.address = std::move(*resolved);
            entry.backoff = {};
            entry.next_attempt = now + refresh_;
        } else {
            // Stale-while-revalidate: the last good address stays served.
            entry.backoff = entry.backoff.count() == 0
                                ? retry_min_
                                : std::min<std::chrono::milliseconds>(entry.backoff * 2,
                                                                      kMaskingResolveRetryMax);
            entry.next_attempt = now + entry.backoff;
        }
    }
}
}  // namespace detail

bool Runtime::Impl::fallback_enabled() const noexcept { return config_.fallback_port != 0; }

bool Runtime::Impl::masking_enabled() const noexcept {
    // Explicit fixed target also arms the probe path, even with auto-SNI off.
    return config_.masking || fallback_enabled();
}

bool Runtime::Impl::append_fallback_bytes(Client& client, io::ByteQueue& queue,
                                          std::span<const std::uint8_t> bytes) {
    if (bytes.empty()) return true;
    if (bytes.size() > queue.max_bytes() - queue.bytes()) return false;
    const auto status = queue.append(bytes);
    if (status != io::AppendStatus::ok) {
        const bool c2b = client.c2b && &queue == &*client.c2b;
        stats_.add_backpressure(c2b ? control::Direction::client_to_server
                                    : control::Direction::server_to_client);
        reaccount(client);
        close_client(client.token);
        return false;
    }
    reaccount(client);
    return true;
}

void Runtime::Impl::refresh_personal_domains() {
    const auto snapshot = users_snapshot_ ? users_snapshot_ : users_.snapshot();
    if (!snapshot || snapshot == domains_snapshot_) return;
    personal_domains_.clear();
    for (const auto& user : snapshot->users) {
        const auto& domain = user.policy.tls_domain;
        if (domain.empty()) continue;
        if (std::find(personal_domains_.begin(), personal_domains_.end(), domain) ==
            personal_domains_.end()) {
            personal_domains_.push_back(domain);
        }
    }
    domains_snapshot_ = snapshot;
}

std::string Runtime::Impl::domain_for_sni(std::string_view sni) {
    if (!config_.tls_domain.empty() && sni_domain_matches(sni, config_.tls_domain)) {
        return config_.tls_domain;
    }
    refresh_personal_domains();
    for (const auto& domain : personal_domains_) {
        if (sni_domain_matches(sni, domain)) return domain;
    }
    return {};
}

std::string Runtime::Impl::fallback_address(std::string_view host) {
    // Literal addresses (the historical loopback backend) bypass DNS entirely.
    if (io::is_numeric_address(host)) return std::string(host);
    // Never resolves here: a cache miss closes the probe (as a failed
    // resolution always did) and asks the background resolver for the name.
    return masking_dns_ ? masking_dns_->address(host) : std::string{};
}

bool Runtime::Impl::start_fallback(Client& client, std::span<const std::uint8_t> prefetched,
                                   Time now, std::span<const std::uint8_t> client_hello) {
    if (!masking_enabled()) return false;
    if (client.phase == Client::Phase::fallback) return true;

    // Room for the largest ClientHello as received: the maximum body plus the
    // header of every fragment record.
    const std::size_t c2b_capacity =
        std::max(config_.connection_queue_bytes,
                 protocol::kFakeTlsMaxClientHello + 5U * protocol::kFakeTlsMaxHelloRecords + 64U);
    if (!client.c2b) {
        client.c2b.emplace(c2b_capacity);
    }
    if (!prefetched.empty()) {
        if (!budget_allows(prefetched.size() + 1024U) ||
            prefetched.size() > client.c2b->max_bytes()) {
            close_client(client.token);
            return true;
        }
        const auto status = client.c2b->append(prefetched);
        if (status != io::AppendStatus::ok) {
            reaccount(client);
            close_client(client.token);
            return true;
        }
    }
    reaccount(client); // account the c2b capacity before any failure close
    client.phase = Client::Phase::fallback;
    client.last_activity = now;
    // Fallback is not a FakeTLS success and never creates a user session. It
    // does release the bounded handshake slot exactly once.
    record_handshake(client, control::HandshakeResult::failure);
    client.hello.clear();
    client.hello.shrink_to_fit();
    reaccount(client);

    client.backend_token = add_target(Target{Kind::fallback_backend, nullptr, client.token});
    std::vector<std::pair<std::string, std::uint16_t>> targets;
    if (fallback_enabled()) {
        targets.emplace_back(config_.fallback_host, config_.fallback_port);
    } else if (config_.masking && !config_.tls_domain.empty()) {
        const auto sni =
            protocol::client_hello_sni(client_hello.empty() ? prefetched : client_hello);
        const std::string ours = sni ? domain_for_sni(*sni) : std::string{};
        if (!ours.empty()) {
            // The configured name, also for a subdomain SNI: a name chosen by
            // the client is never resolved, so a probe cannot make the proxy
            // look up arbitrary names.
            targets.emplace_back(ours, 443U);
        } else {
            // A foreign or missing SNI, or bytes that are not TLS at all: the
            // real site of tls_domain answers, as it would if the probe had
            // reached it directly. Closing instead (an RST for the unread
            // bytes) would single this server out. The target is fixed, so
            // this never relays to an address chosen by the client.
            targets.emplace_back(config_.tls_domain, 443U);
        }
    }
    if (targets.empty()) {
        if (client.watched) watch_log(client, "masking", "target=none");
        close_client(client.token);
        return true;
    }
    auto connected = io::FdResult{};
    std::unique_ptr<protocol::Socks5Client> socks;
    bool dialled = false;
    const auto override_target = fallback_enabled() ? std::nullopt : masking_override();
    for (const auto& [host, target_port] : targets) {
        const std::string address =
            override_target ? override_target->host : fallback_address(host);
        std::uint16_t port = override_target ? override_target->port : target_port;
        if (!override_target && !fallback_enabled()) {
            if (const auto hooks = masking_hooks(); hooks && hooks->port != 0) port = hooks->port;
        }
        if (address.empty()) continue;
        auto dialed = dial(config_.masking_scope, address, port);
        auto attempt = std::move(dialed.connected);
        if (client.watched) {
            std::string via;
            if (dialed.upstream != nullptr && !dialed.upstream->name.empty()) {
                via = " via=" + dialed.upstream->name;
            }
            watch_log(client, "masking", "target=" + host + ":" + std::to_string(port) + via +
                                             (attempt.ok() ? "" : " connect_failed"));
        }
        if (attempt.ok()) {
            connected = std::move(attempt);
            socks = std::move(dialed.socks);
            dialled = true;
            break;
        }
    }
    if (!dialled) {
        close_client(client.token);
        return true;
    }
    client.backend = std::move(connected.fd);
    client.backend_socks = std::move(socks);
    client.backend_connecting = true;
    client.deadline_kind = Client::DeadlineKind::fallback_connect;
    deadlines_.set(client.backend_token, now + config_.handshake_timeout);
    client.fallback_tracked = true;
    fallback_clients_.push_back(client.token);
    reaccount(client);
    update_fallback_client_interest(client);
    update_fallback_backend_interest(client);
    if (!connected.in_progress) on_fallback_connected(client, now);
    return true;
}

void Runtime::Impl::update_fallback_client_interest(Client& client) {
    if (client.token == 0 || !client.fd.valid()) return;
    std::uint32_t desired = 0;
    const bool source_room = client.c2b && client.c2b->bytes() < client.c2b->max_bytes();
    if (!client.read_eof && !client.draining && !client.budget_paused &&
        !client.close_requested && source_room) {
        desired |= EPOLLIN;
    }
    if (!client.fin_pending && !client.read_eof) desired |= EPOLLRDHUP;
    if (client.out && !client.out->empty()) desired |= EPOLLOUT;
    set_interest(client.token, client.fd.get(), client.armed, desired);
}

void Runtime::Impl::update_fallback_backend_interest(Client& client) {
    if (client.backend_token == 0 || !client.backend.valid()) return;
    std::uint32_t desired = 0;
    if (client.backend_connecting) {
        // Through SOCKS5 the proxy's handshake reply is read after the connect;
        // nothing of c2b is written before the handshake is done.
        desired |= client.backend_socks && client.backend_socks->started() ? EPOLLIN : EPOLLOUT;
    } else {
        const bool room = client.out && client.out->bytes() < client.out->max_bytes();
        if (!client.backend_eof && !client.backend_budget_paused && room) desired |= EPOLLIN;
        if (!client.backend_fin_pending && !client.backend_eof) desired |= EPOLLRDHUP;
        if (client.c2b && !client.c2b->empty()) desired |= EPOLLOUT;
    }
    set_interest(client.backend_token, client.backend.get(), client.backend_armed, desired);
}

void Runtime::Impl::on_fallback_connected(Client& client, Time now) {
    if (!client.backend.valid()) {
        close_client(client.token);
        return;
    }
    int error = 0;
    socklen_t length = sizeof(error);
    if (::getsockopt(client.backend.get(), SOL_SOCKET, SO_ERROR, &error, &length) != 0 ||
        error != 0) {
        close_client(client.token);
        return;
    }
    if (client.backend_socks &&
        client.backend_socks->status() != protocol::Socks5Client::Status::Done) {
        // Connected to the SOCKS5 proxy; entered again once its handshake is Done.
        if (client.backend_socks->started()) return;
        if (socks_start(client.backend.get(), *client.backend_socks) == SocksProgress::failed) {
            close_client(client.token);
            return;
        }
        update_fallback_backend_interest(client);
        return;
    }
    client.backend_connecting = false;
    client.last_activity = now;
    // The fallback backend carries the same small MTProto records as the ME
    // route; Nagle would add the same avoidable latency here.
    (void)io::set_tcp_nodelay(client.backend.get());
    (void)io::set_tcp_keepalive(client.backend.get());
    client.deadline_kind = Client::DeadlineKind::fallback_idle;
    deadlines_.set(client.backend_token, now + config_.idle_timeout);
    update_fallback_client_interest(client);
    update_fallback_backend_interest(client);
    pump_fallback_c2b(client);
    if (clients_.find(client.token) != clients_.end()) pump_fallback_b2c(client);
}

void Runtime::Impl::read_fallback_client(Client& client, Time now) {
    if (client.draining || client.budget_paused || client.read_eof || client.close_requested) return;
    if (!client.c2b) return;
    if (!budget_allows(detail::kClientReadReservation)) {
        client.budget_paused = true;
        paused_clients_.push_back(client.token);
        stats_.add_backpressure(control::Direction::client_to_server);
        update_fallback_client_interest(client);
        return;
    }
    const std::uint64_t token = client.token;
    std::size_t total = 0;
    while (total < detail::kReadBatch) {
        const std::size_t room = client.c2b->max_bytes() - client.c2b->bytes();
        if (room == 0) {
            stats_.add_backpressure(control::Direction::client_to_server);
            break;
        }
        const std::size_t limit = std::min(detail::kReadBatch - total, room);
        const ssize_t received = ::recv(client.fd.get(), read_buffer_.data(), limit, MSG_DONTWAIT);
        if (received > 0) {
            const auto bytes = static_cast<std::size_t>(received);
            total += bytes;
            touch(client, now);
            if (!append_fallback_bytes(
                    client, *client.c2b,
                    std::span<const std::uint8_t>(read_buffer_).first(bytes))) {
                return;
            }
        } else if (received == 0) {
            client.read_eof = true;
            client.read_eof_at = now;
            client.fin_pending = true;
            update_fallback_client_interest(client);
            break;
        } else if (errno == EINTR) {
            continue;
        } else if (errno == EAGAIN || errno == EWOULDBLOCK) {
            break;
        } else {
            close_client(token);
            return;
        }
    }
    reaccount(client);
    update_fallback_client_interest(client);
    pump_fallback_c2b(client);
}

void Runtime::Impl::read_fallback_backend(Client& client, Time now) {
    if (client.backend_connecting || client.backend_eof) return;
    if (!client.out) return;
    if (!budget_allows(detail::kClientReadReservation)) {
        if (!client.backend_budget_paused) {
            client.backend_budget_paused = true;
            paused_clients_.push_back(client.token);
        }
        stats_.add_backpressure(control::Direction::server_to_client);
        update_fallback_backend_interest(client);
        return;
    }
    const std::uint64_t token = client.token;
    std::size_t total = 0;
    while (total < detail::kReadBatch) {
        const std::size_t room = client.out->max_bytes() - client.out->bytes();
        if (room == 0) {
            stats_.add_backpressure(control::Direction::server_to_client);
            break;
        }
        const std::size_t limit = std::min(detail::kReadBatch - total, room);
        const ssize_t received = ::recv(client.backend.get(), read_buffer_.data(), limit,
                                        MSG_DONTWAIT);
        if (received > 0) {
            const auto bytes = static_cast<std::size_t>(received);
            total += bytes;
            touch(client, now);
            if (!append_fallback_bytes(
                    client, *client.out,
                    std::span<const std::uint8_t>(read_buffer_).first(bytes))) {
                return;
            }
        } else if (received == 0) {
            client.backend_eof = true;
            client.backend_fin_pending = true;
            update_fallback_backend_interest(client);
            break;
        } else if (errno == EINTR) {
            continue;
        } else if (errno == EAGAIN || errno == EWOULDBLOCK) {
            break;
        } else {
            close_client(token);
            return;
        }
    }
    reaccount(client);
    update_fallback_backend_interest(client);
    pump_fallback_b2c(client);
}

void Runtime::Impl::pump_fallback_c2b(Client& client) {
    const std::uint64_t token = client.token;
    if (client.backend.valid() && !client.backend_connecting && client.c2b) {
        while (!client.c2b->empty()) {
            const auto result = client.c2b->flush_to(client.backend.get(), detail::kWriteBatch);
            if (result.status == io::FlushStatus::error) {
                close_client(token);
                return;
            }
            if (result.bytes_written > 0) touch(client, Clock::now());
            if (result.status != io::FlushStatus::drained) break;
        }
        if (client.c2b->empty() && client.read_eof && !client.backend_write_shutdown) {
            ::shutdown(client.backend.get(), SHUT_WR);
            client.backend_write_shutdown = true;
        }
    }
    reaccount(client);
    update_fallback_client_interest(client);
    update_fallback_backend_interest(client);
}

void Runtime::Impl::pump_fallback_b2c(Client& client) {
    const std::uint64_t token = client.token;
    if (client.out && client.fd.valid()) {
        while (!client.out->empty()) {
            const auto result = client.out->flush_to(client.fd.get(), detail::kWriteBatch);
            if (result.status == io::FlushStatus::error) {
                close_client(token);
                return;
            }
            if (result.bytes_written > 0) touch(client, Clock::now());
            if (result.status != io::FlushStatus::drained) break;
        }
        if (client.out->empty() && client.backend_eof && !client.client_write_shutdown) {
            ::shutdown(client.fd.get(), SHUT_WR);
            client.client_write_shutdown = true;
        }
    }
    reaccount(client);
    update_fallback_client_interest(client);
    update_fallback_backend_interest(client);
}

void Runtime::Impl::handle_fallback_client(Client& client, std::uint32_t events, Time now) {
    const std::uint64_t token = client.token;
    if ((events & EPOLLERR) != 0) {
        close_client(token);
        return;
    }
    const bool client_hup = (events & EPOLLHUP) != 0;
    // HUP can arrive together with the last readable bytes. Drain first; a full
    // HUP means the client is gone, so the pair is closed after that drain.
    if ((events & (EPOLLIN | EPOLLHUP)) != 0) {
        read_fallback_client(client, now);
        if (clients_.find(token) == clients_.end()) return;
    }
    if (client_hup) {
        close_client(token);
        return;
    }
    if ((events & EPOLLRDHUP) != 0) {
        client.fin_pending = true;
        client.fin_at = now;
        update_fallback_client_interest(client);
    }
    if ((events & EPOLLOUT) != 0) {
        pump_fallback_b2c(client);
        if (clients_.find(token) == clients_.end()) return;
        pump_fallback_c2b(client);
    }
}

void Runtime::Impl::handle_fallback_backend(Client& client, std::uint32_t events, Time now) {
    const std::uint64_t token = client.token;
    if ((events & EPOLLERR) != 0) {
        close_client(token);
        return;
    }
    if (client.backend_connecting) {
        if ((events & EPOLLHUP) != 0) {
            close_client(token);
            return;
        }
        if (client.backend_socks && client.backend_socks->started()) {
            if ((events & (EPOLLIN | EPOLLRDHUP)) == 0) return;
            const auto progress = socks_read(client.backend.get(), *client.backend_socks);
            if (progress == SocksProgress::failed) {
                close_client(token);
            } else if (progress == SocksProgress::done) {
                on_fallback_connected(client, now);
            }
            return;
        }
        if ((events & EPOLLOUT) != 0) on_fallback_connected(client, now);
        return;
    }
    const bool backend_hup = (events & EPOLLHUP) != 0;
    if ((events & (EPOLLIN | EPOLLHUP)) != 0) {
        read_fallback_backend(client, now);
        if (clients_.find(token) == clients_.end()) return;
    }
    if (backend_hup) {
        // Backend fully closed: keep the client pair only long enough to flush
        // the already-read B2C bytes, then close. This avoids a level-triggered
        // HUP spin and an unbounded retained pair.
        client.backend_eof = true;
        close_fallback_backend(client);
        client.deadline_kind = Client::DeadlineKind::fallback_idle;
        deadlines_.set(client.token, now + config_.idle_timeout);
        pump_fallback_b2c(client);
        return;
    }
    if ((events & EPOLLRDHUP) != 0) {
        client.backend_fin_pending = true;
        client.backend_fin_at = now;
        update_fallback_backend_interest(client);
    }
    if ((events & EPOLLOUT) != 0) pump_fallback_c2b(client);
}

void Runtime::Impl::close_fallback_backend(Client& client) {
    if (client.backend_token == 0 && !client.backend.valid()) return;
    deadlines_.erase(client.backend_token);
    if (client.backend.valid()) {
        set_interest(client.backend_token, client.backend.get(), client.backend_armed, 0);
    }
    remove_target(client.backend_token);
    client.backend.close();
    client.backend_token = 0;
    client.backend_armed = 0;
    client.backend_connecting = false;
    client.backend_eof = true;
}

void Runtime::Impl::on_fallback_deadline(Client& client, Time now) {
    if (client.deadline_kind == Client::DeadlineKind::fallback_connect) {
        close_client(client.token);
        return;
    }
    if (client.deadline_kind != Client::DeadlineKind::fallback_idle) return;
    const auto idle = config_.idle_timeout;
    if (now - client.last_activity >= idle) {
        close_client(client.token);
    } else {
        const std::uint64_t token =
            client.backend_token != 0 ? client.backend_token : client.token;
        deadlines_.set(token, client.last_activity + idle);
    }
}

void Runtime::Impl::finish_fallback_pairs(Time now) {
    if (fallback_clients_.empty()) return;
    std::vector<std::uint64_t>& remaining = fallback_remaining_;
    remaining.clear();
    for (const std::uint64_t token : fallback_clients_) {
        const auto found = clients_.find(token);
        if (found == clients_.end()) continue;
        Client& client = *found->second;
        if (client.phase != Client::Phase::fallback) continue;
        if (client.fin_pending && !client.read_eof &&
            now >= client.fin_at + config_.shutdown_timeout) {
            stats_.add_backpressure(control::Direction::client_to_server);
            stats_.connection_rejected(control::RejectReason::other);
            close_client(token);
            continue;
        }
        if (client.backend_fin_pending && !client.backend_eof &&
            now >= client.backend_fin_at + config_.shutdown_timeout) {
            stats_.add_backpressure(control::Direction::server_to_client);
            stats_.connection_rejected(control::RejectReason::other);
            close_client(token);
            continue;
        }
        pump_fallback_c2b(client);
        if (clients_.find(token) == clients_.end()) continue;
        pump_fallback_b2c(*clients_.find(token)->second);
        if (clients_.find(token) == clients_.end()) continue;
        const bool c2b_empty = !client.c2b || client.c2b->empty();
        const bool b2c_empty = !client.out || client.out->empty();
        const bool backend_gone = !client.backend.valid();
        const bool done =
            b2c_empty && ((client.read_eof && client.backend_eof && c2b_empty) || backend_gone);
        if (done || client.close_requested || (stopping_ && now >= shutdown_deadline_)) {
            close_client(token);
        } else {
            remaining.push_back(token);
        }
    }
    fallback_clients_.swap(remaining);
    remaining.clear();
}

} // namespace mtdd
