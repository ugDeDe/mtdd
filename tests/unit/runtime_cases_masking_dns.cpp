#include "../support/runtime_fixture.hpp"

#include <condition_variable>
#include <map>

// ---------------------------------------------------------------------------
// Masking-target DNS: resolution runs on a background thread, never on a
// reactor. A fake resolver (detail::set_masking_resolve_hooks_for_test) stands
// in for getaddrinfo; no real name is ever resolved.
// ---------------------------------------------------------------------------

namespace {

constexpr std::string_view kPersonalDomain = "front.test";

// Answers 127.0.0.1 for the names it knows. A name can be made slow, failing,
// or gated (blocked until open_gate()). Counts every call per name.
class FakeDns {
public:
    void answer(std::string name, std::chrono::milliseconds delay = 0ms) {
        const std::lock_guard lock{mutex_};
        names_[std::move(name)] = delay;
    }
    void fail(const std::string& name) {
        const std::lock_guard lock{mutex_};
        failing_[name] = true;
    }
    void close_gate() {
        const std::lock_guard lock{mutex_};
        gated_ = true;
    }
    void open_gate() {
        {
            const std::lock_guard lock{mutex_};
            gated_ = false;
        }
        changed_.notify_all();
    }
    std::uint64_t calls(const std::string& name) const {
        const std::lock_guard lock{mutex_};
        const auto found = calls_.find(name);
        return found == calls_.end() ? 0 : found->second;
    }
    std::map<std::string, std::uint64_t> all_calls() const {
        const std::lock_guard lock{mutex_};
        return calls_;
    }

    std::optional<std::string> resolve(const std::string& name) {
        std::chrono::milliseconds delay{0};
        {
            std::unique_lock lock{mutex_};
            ++calls_[name];
            // Bounded so a broken test cannot hang the runtime forever.
            changed_.wait_for(lock, 5s, [this] { return !gated_; });
            const auto found = names_.find(name);
            if (found == names_.end() || failing_[name]) return std::nullopt;
            delay = found->second;
        }
        if (delay.count() > 0) std::this_thread::sleep_for(delay);
        return std::string("127.0.0.1");
    }

private:
    mutable std::mutex mutex_;
    std::condition_variable changed_;
    std::map<std::string, std::chrono::milliseconds> names_;
    std::map<std::string, bool> failing_;
    std::map<std::string, std::uint64_t> calls_;
    bool gated_{false};
};

// Installs `dns` as the masking resolver; automatic targets dial `port`.
struct DnsHooksScope {
    DnsHooksScope(FakeDns& dns, std::uint16_t port,
                  std::chrono::milliseconds refresh = mtdd::detail::kFallbackResolveTtl) {
        mtdd::detail::MaskingResolveHooks hooks;
        hooks.resolve = [&dns](const std::string& name) { return dns.resolve(name); };
        hooks.refresh = refresh;
        hooks.port = port;
        mtdd::detail::set_masking_resolve_hooks_for_test(std::move(hooks));
    }
    ~DnsHooksScope() { mtdd::detail::set_masking_resolve_hooks_for_test(std::nullopt); }
    DnsHooksScope(const DnsHooksScope&) = delete;
    DnsHooksScope& operator=(const DnsHooksScope&) = delete;
};

std::uint32_t now_timestamp() {
    return static_cast<std::uint32_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch())
            .count());
}

Bytes probe_hello(std::string_view sni) {
    // Differs from every user's secret in every byte: never authenticates.
    A16 wrong = secret_bytes();
    for (auto& byte : wrong) byte = static_cast<std::uint8_t>(byte ^ 0xaa);
    return make_client_hello(wrong, now_timestamp(), sni, 3);
}

// Masking target that serves connections concurrently (EchoBackend serves one
// at a time), so a long-lived relay and later probes can coexist.
class ConcurrentEcho {
public:
    ConcurrentEcho() {
        auto listener = mtdd::io::listen_tcp("127.0.0.1", 0);
        if (!listener.ok()) throw std::runtime_error("echo cannot listen");
        listener_ = std::move(listener.fd);
        const auto local = mtdd::io::local_endpoint(listener_.get());
        if (!local) throw std::runtime_error("echo has no port");
        port_ = local->port;
        acceptor_ = std::thread([this] { accept_loop(); });
    }
    ~ConcurrentEcho() {
        stop_.store(true);
        if (acceptor_.joinable()) acceptor_.join();
        for (auto& worker : workers_) worker.join();
    }
    ConcurrentEcho(const ConcurrentEcho&) = delete;
    ConcurrentEcho& operator=(const ConcurrentEcho&) = delete;

    std::uint16_t port() const { return port_; }
    std::uint64_t accepted() const { return accepted_.load(); }

private:
    void accept_loop() {
        while (!stop_.load()) {
            pollfd entry{listener_.get(), POLLIN, 0};
            if (::poll(&entry, 1, 50) <= 0) continue;
            const int fd = ::accept4(listener_.get(), nullptr, nullptr, SOCK_CLOEXEC);
            if (fd < 0) continue;
            ++accepted_;
            workers_.emplace_back([this, fd] { serve(fd); });
        }
    }
    void serve(int fd) {
        std::array<std::uint8_t, 16384> buffer{};
        while (!stop_.load()) {
            pollfd entry{fd, POLLIN, 0};
            if (::poll(&entry, 1, 50) <= 0) continue;
            const ssize_t got = ::recv(fd, buffer.data(), buffer.size(), 0);
            if (got <= 0) break;
            if (!send_all(fd, std::span<const std::uint8_t>(buffer).first(
                                  static_cast<std::size_t>(got)))) {
                break;
            }
        }
        ::close(fd);
    }

    mtdd::io::UniqueFd listener_;
    std::uint16_t port_{0};
    std::atomic<bool> stop_{false};
    std::atomic<std::uint64_t> accepted_{0};
    std::thread acceptor_;
    std::vector<std::thread> workers_;  // acceptor thread only, then joined
};

// A probe (unauthenticated ClientHello for `sni`): true when the masking
// target echoed it back within `timeout_ms`.
bool probe_masked(std::uint16_t port, std::string_view sni, int timeout_ms = 1500) {
    const int fd = connect_loopback(port);
    if (fd < 0) return false;
    const Bytes wire = probe_hello(sni);
    bool ok = send_all(fd, wire);
    Bytes echoed(wire.size());
    ok = ok && recv_exact(fd, echoed.data(), echoed.size(), timeout_ms) && echoed == wire;
    ::close(fd);
    return ok;
}

// Retries probes until one is masked: the first may arrive on a cold cache.
bool wait_masked(std::uint16_t port, std::string_view sni) {
    return wait_for([&] { return probe_masked(port, sni, 500); }, 5000ms);
}

std::uint64_t total(const std::map<std::string, std::uint64_t>& calls) {
    std::uint64_t sum = 0;
    for (const auto& [name, count] : calls) sum += count;
    return sum;
}

void set_personal_domain(Daemon& daemon, std::string domain) {
    mtdd::control::UpdateUserRequest update;
    update.name = "alice";
    update.policy.tls_domain = std::move(domain);
    ASSERT_TRUE(daemon.services.store->update_user(update).ok());
}

void masking_on(mtdd::Config& config) { config.masking = true; }

} // namespace

TEST(MaskingDns, SlowResolveStallsNeitherRelayNorCachedProbe) {
    FakeDns dns;
    dns.answer(std::string(kDomain));
    dns.answer(std::string(kPersonalDomain), 2000ms);
    ConcurrentEcho echo;
    DnsHooksScope hooks(dns, echo.port());
    Daemon daemon(1, false, masking_on);
    ASSERT_TRUE(daemon.services.add_user("alice", std::string(kSecretHex)));
    ASSERT_TRUE(wait_masked(daemon.port(), kDomain));

    // An established masked pair on the (single) reactor.
    const int relay = connect_loopback(daemon.port());
    ASSERT_GE(relay, 0);
    const Bytes hello = probe_hello(kDomain);
    ASSERT_TRUE(send_all(relay, hello));
    Bytes echoed(hello.size());
    ASSERT_TRUE(recv_exact(relay, echoed.data(), echoed.size(), 2000));

    // A probe for a name whose resolution takes 2 s.
    set_personal_domain(daemon, std::string(kPersonalDomain));
    const int slow = connect_loopback(daemon.port());
    ASSERT_GE(slow, 0);
    ASSERT_TRUE(send_all(slow, probe_hello(kPersonalDomain)));
    std::this_thread::sleep_for(100ms);

    auto start = std::chrono::steady_clock::now();
    const Bytes ping(64, 0x5a);
    ASSERT_TRUE(send_all(relay, ping));
    Bytes pong(ping.size());
    EXPECT_TRUE(recv_exact(relay, pong.data(), pong.size(), 3000));
    EXPECT_LT(std::chrono::steady_clock::now() - start, 500ms) << "relay stalled by DNS";

    start = std::chrono::steady_clock::now();
    EXPECT_TRUE(probe_masked(daemon.port(), kDomain, 3000));
    EXPECT_LT(std::chrono::steady_clock::now() - start, 500ms) << "cached probe stalled by DNS";
    ::close(slow);
    ::close(relay);
}

TEST(MaskingDns, AlternatingGlobalAndPersonalDomainsHitTheCache) {
    FakeDns dns;
    dns.answer(std::string(kDomain));
    dns.answer(std::string(kPersonalDomain));
    ConcurrentEcho echo;
    DnsHooksScope hooks(dns, echo.port());
    Daemon daemon(1, false, masking_on);
    ASSERT_TRUE(daemon.services.add_user("alice", std::string(kSecretHex)));
    set_personal_domain(daemon, std::string(kPersonalDomain));
    ASSERT_TRUE(wait_masked(daemon.port(), kDomain));
    ASSERT_TRUE(wait_masked(daemon.port(), kPersonalDomain));

    const auto before = dns.all_calls();
    for (int round = 0; round < 4; ++round) {
        EXPECT_TRUE(probe_masked(daemon.port(), kDomain));
        EXPECT_TRUE(probe_masked(daemon.port(), kPersonalDomain));
    }
    EXPECT_EQ(total(dns.all_calls()), total(before));
}

TEST(MaskingDns, SubdomainProbesUseTheParentAddressWithoutResolving) {
    FakeDns dns;
    dns.answer(std::string(kDomain));
    dns.answer(std::string(kPersonalDomain));
    ConcurrentEcho echo;
    DnsHooksScope hooks(dns, echo.port());
    Daemon daemon(1, false, masking_on);
    ASSERT_TRUE(daemon.services.add_user("alice", std::string(kSecretHex)));
    set_personal_domain(daemon, std::string(kPersonalDomain));
    ASSERT_TRUE(wait_masked(daemon.port(), kDomain));
    ASSERT_TRUE(wait_masked(daemon.port(), kPersonalDomain));

    const auto before = dns.all_calls();
    for (int i = 0; i < 8; ++i) {
        const std::string random = "r" + std::to_string(i) + "x";
        EXPECT_TRUE(probe_masked(daemon.port(), random + "." + std::string(kDomain)));
        EXPECT_TRUE(probe_masked(daemon.port(), random + "." + std::string(kPersonalDomain)));
    }
    const auto after = dns.all_calls();
    EXPECT_EQ(total(after), total(before));
    for (const auto& [name, count] : after) {
        EXPECT_TRUE(name == kDomain || name == kPersonalDomain)
            << "client-chosen name resolved: " << name << " x" << count;
    }
}

TEST(MaskingDns, RefreshFailureKeepsServingTheLastGoodAddress) {
    FakeDns dns;
    dns.answer(std::string(kDomain));
    ConcurrentEcho echo;
    DnsHooksScope hooks(dns, echo.port(), 200ms);
    Daemon daemon(1, false, masking_on);
    ASSERT_TRUE(wait_masked(daemon.port(), kDomain));

    const auto good = dns.calls(std::string(kDomain));
    dns.fail(std::string(kDomain));
    // Refreshed (and failing) in the background, with no probe.
    EXPECT_TRUE(wait_for([&] { return dns.calls(std::string(kDomain)) >= good + 2; }, 3000ms));
    EXPECT_TRUE(probe_masked(daemon.port(), kDomain));
    EXPECT_TRUE(probe_masked(daemon.port(), "sub." + std::string(kDomain)));
}

TEST(MaskingDns, ShortRefreshWithSlowAnswersNeverStallsTheReactor) {
    // Models a domain served by a rotating A-record pool with a short TTL:
    // the name is re-resolved continuously and every answer is slow. Relay
    // and probes on the reactor must not wait for any of those lookups.
    FakeDns dns;
    dns.answer(std::string(kDomain), 300ms);
    ConcurrentEcho echo;
    DnsHooksScope hooks(dns, echo.port(), 50ms);
    Daemon daemon(1, false, masking_on);
    ASSERT_TRUE(wait_masked(daemon.port(), kDomain));

    const int relay = connect_loopback(daemon.port());
    ASSERT_GE(relay, 0);
    const Bytes hello = probe_hello(kDomain);
    ASSERT_TRUE(send_all(relay, hello));
    Bytes echoed(hello.size());
    ASSERT_TRUE(recv_exact(relay, echoed.data(), echoed.size(), 2000));

    const auto first = dns.calls(std::string(kDomain));
    auto worst = std::chrono::steady_clock::duration::zero();
    for (int i = 0; i < 10; ++i) {
        auto start = std::chrono::steady_clock::now();
        const Bytes ping(64, static_cast<std::uint8_t>(i));
        ASSERT_TRUE(send_all(relay, ping));
        Bytes pong(ping.size());
        EXPECT_TRUE(recv_exact(relay, pong.data(), pong.size(), 3000));
        worst = std::max(worst, std::chrono::steady_clock::now() - start);
        start = std::chrono::steady_clock::now();
        EXPECT_TRUE(probe_masked(daemon.port(), kDomain, 3000));
        worst = std::max(worst, std::chrono::steady_clock::now() - start);
        std::this_thread::sleep_for(100ms);
    }
    EXPECT_LT(worst, 200ms) << "reactor waited for a refresh";
    // The refreshes did happen, in the background.
    EXPECT_GE(dns.calls(std::string(kDomain)), first + 3);
    ::close(relay);
}

TEST(MaskingDns, ColdCacheClosesProbeAndResolvesInTheBackground) {
    FakeDns dns;
    dns.answer(std::string(kDomain));
    dns.close_gate();
    ConcurrentEcho echo;
    DnsHooksScope hooks(dns, echo.port());
    Daemon daemon(1, false, masking_on);

    // Nothing cached yet: the probe is closed at once, not parked.
    const int fd = connect_loopback(daemon.port());
    ASSERT_GE(fd, 0);
    ASSERT_TRUE(send_all(fd, probe_hello(kDomain)));
    EXPECT_TRUE(wait_closed(fd, 1000));
    ::close(fd);
    EXPECT_EQ(echo.accepted(), 0U);
    EXPECT_TRUE(wait_for([&] { return dns.calls(std::string(kDomain)) >= 1; }, 2000ms));

    dns.open_gate();
    EXPECT_TRUE(wait_masked(daemon.port(), kDomain));
}

TEST(MaskingDns, PersonalDomainsFollowTheUserSnapshot) {
    FakeDns dns;
    dns.answer(std::string(kDomain));
    dns.answer(std::string(kPersonalDomain));
    ConcurrentEcho echo;
    DnsHooksScope hooks(dns, echo.port());
    Daemon daemon(1, false, masking_on);
    ASSERT_TRUE(daemon.services.add_user("alice", std::string(kSecretHex)));

    // Added: resolved without a restart and without any probe.
    set_personal_domain(daemon, std::string(kPersonalDomain));
    ASSERT_TRUE(wait_for([&] { return dns.calls(std::string(kPersonalDomain)) >= 1; }, 3000ms));
    // Removed, then added again: the entry was evicted, so it resolves anew
    // (a retained entry would stay fresh for the whole refresh period).
    set_personal_domain(daemon, "");
    std::this_thread::sleep_for(1500ms);
    set_personal_domain(daemon, std::string(kPersonalDomain));
    EXPECT_TRUE(wait_for([&] { return dns.calls(std::string(kPersonalDomain)) >= 2; }, 3000ms));
    EXPECT_TRUE(wait_masked(daemon.port(), kPersonalDomain));
}

TEST(MaskingDns, ShutdownIsBoundedByOneBlockedResolve) {
    FakeDns dns;
    dns.answer(std::string(kDomain), 1500ms);
    ConcurrentEcho echo;
    DnsHooksScope hooks(dns, echo.port());
    Daemon daemon(1, false, masking_on);
    ASSERT_TRUE(wait_for([&] { return dns.calls(std::string(kDomain)) >= 1; }, 2000ms));

    const auto start = std::chrono::steady_clock::now();
    daemon.stop();
    EXPECT_LT(std::chrono::steady_clock::now() - start, 2500ms);
}
