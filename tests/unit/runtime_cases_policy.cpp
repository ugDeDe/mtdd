#include "../support/runtime_fixture.hpp"

#include <mtdd/runtime_support.hpp>

#include "../support/fake_direct_dc.hpp"

#include <arpa/inet.h>

#include <atomic>
#include <thread>

// ---------------------------------------------------------------------------
// Per-user policy: expiry, data quota, unique-IP limit and rate limit
// ---------------------------------------------------------------------------

namespace {

struct PolicyDirectEndpointScope {
    explicit PolicyDirectEndpointScope(std::uint16_t port) {
        mtdd::detail::set_direct_endpoint_override(
            mtdd::detail::DirectEndpointOverride{"127.0.0.1", port});
    }
    ~PolicyDirectEndpointScope() { mtdd::detail::set_direct_endpoint_override(std::nullopt); }
    PolicyDirectEndpointScope(const PolicyDirectEndpointScope&) = delete;
    PolicyDirectEndpointScope& operator=(const PolicyDirectEndpointScope&) = delete;
};

void enable_policy_direct(mtdd::Config& config) {
    config.direct_fallback_enabled = true;
    config.direct_fallback_dcs = {2};
    config.max_connections = 8;
    config.max_handshakes = 8;
}

bool add_policy_user(Daemon& daemon, const mtdd::control::UserPolicy& policy,
                     std::optional<std::uint32_t> max_connections = std::nullopt) {
    mtdd::control::CreateUserRequest request;
    request.name = "alice";
    request.secret = std::string(kSecretHex);
    request.policy = policy;
    request.max_connections = max_connections;
    return daemon.services.store->create_user(request).ok();
}

bool patch_policy(Daemon& daemon, const mtdd::control::UserPolicyPatch& patch) {
    mtdd::control::UpdateUserRequest request;
    request.name = "alice";
    request.policy = patch;
    return daemon.services.store->update_user(request).ok();
}

std::int64_t unix_seconds() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

std::uint64_t rejected(Daemon& daemon, const char* reason) {
    return stat_counter(daemon.services.stats, "rejected", reason);
}

int connect_from(const char* source, std::uint16_t port) {
    const int fd = ::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;
    sockaddr_in local{};
    local.sin_family = AF_INET;
    ::inet_pton(AF_INET, source, &local.sin_addr);
    sockaddr_in remote{};
    remote.sin_family = AF_INET;
    remote.sin_port = htons(port);
    remote.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (::bind(fd, reinterpret_cast<const sockaddr*>(&local), sizeof(local)) != 0 ||
        ::connect(fd, reinterpret_cast<const sockaddr*>(&remote), sizeof(remote)) != 0) {
        ::close(fd);
        return -1;
    }
    timeval timeout{};
    timeout.tv_sec = 3;
    ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    ::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    return fd;
}

} // namespace

TEST(RuntimePolicy, ExpiredUserIsRejectedAtAdmissionWithoutHoldingASlot) {
    Daemon daemon(1, false);
    mtdd::control::UserPolicy policy;
    policy.expires_at = 1;
    ASSERT_TRUE(add_policy_user(daemon, policy, 1));
    TestClient client(daemon.port(), secret_bytes());
    ASSERT_TRUE(client.valid());
    EXPECT_FALSE(client.send_hello());
    EXPECT_TRUE(wait_for([&] { return rejected(daemon, "user_expired") >= 1U; }, 2s));
    EXPECT_EQ(rejected(daemon, "overload"), 0U);
    EXPECT_TRUE(wait_for([&] {
        return daemon.services.stats.snapshot().users.at("alice").active_connections == 0;
    }, 2s));
}

TEST(RuntimePolicy, ExhaustedQuotaIsRejectedAtAdmission) {
    Daemon daemon(1, false);
    mtdd::control::UserPolicy policy;
    policy.data_quota_bytes = 1000;
    ASSERT_TRUE(add_policy_user(daemon, policy));
    {
        TestClient under(daemon.port(), secret_bytes());
        ASSERT_TRUE(under.valid());
        EXPECT_TRUE(under.send_hello()) << "usage below the quota must be admitted";
    }
    daemon.services.stats.user("alice")->set_quota_used_bytes(1000);
    TestClient client(daemon.port(), secret_bytes());
    ASSERT_TRUE(client.valid());
    EXPECT_FALSE(client.send_hello(0, 1));
    EXPECT_TRUE(wait_for([&] { return rejected(daemon, "user_quota_exceeded") >= 1U; }, 2s));

    // Resetting the counter admits the user again.
    daemon.services.stats.user("alice")->reset_quota();
    TestClient again(daemon.port(), secret_bytes());
    ASSERT_TRUE(again.valid());
    EXPECT_TRUE(again.send_hello(0, 2));
}

TEST(RuntimePolicy, PerUserConnectionLimitUsesItsOwnReason) {
    Daemon daemon(1, false);
    ASSERT_TRUE(add_policy_user(daemon, {}, 1));
    TestClient first(daemon.port(), secret_bytes());
    ASSERT_TRUE(first.valid());
    ASSERT_TRUE(first.send_hello());
    TestClient second(daemon.port(), secret_bytes());
    ASSERT_TRUE(second.valid());
    EXPECT_FALSE(second.send_hello(0, 1));
    EXPECT_TRUE(wait_for([&] { return rejected(daemon, "user_connection_limit") >= 1U; }, 2s));
    EXPECT_EQ(rejected(daemon, "overload"), 0U);
}

TEST(RuntimePolicy, LiveSessionIsRevokedWhenTheUserExpires) {
    Daemon daemon(1, false);
    mtdd::control::UserPolicy policy;
    policy.expires_at = unix_seconds() + 2;
    ASSERT_TRUE(add_policy_user(daemon, policy));
    TestClient client(daemon.port(), secret_bytes());
    ASSERT_TRUE(client.valid());
    ASSERT_TRUE(client.send_hello());
    // Expiry is time driven (1 Hz sweep), not snapshot driven.
    EXPECT_TRUE(client.wait_closed_for(6000));
    EXPECT_TRUE(wait_for([&] {
        return daemon.services.stats.snapshot().users.at("alice").active_connections == 0;
    }, 2s));
    TestClient late(daemon.port(), secret_bytes());
    ASSERT_TRUE(late.valid());
    EXPECT_FALSE(late.send_hello(0, 1));
    EXPECT_TRUE(wait_for([&] { return rejected(daemon, "user_expired") >= 1U; }, 2s));
}

TEST(RuntimePolicy, LiveSessionIsRevokedWhenTheQuotaIsExceeded) {
    Daemon daemon(1, false);
    mtdd::control::UserPolicy policy;
    policy.data_quota_bytes = 1000;
    ASSERT_TRUE(add_policy_user(daemon, policy));
    TestClient client(daemon.port(), secret_bytes());
    ASSERT_TRUE(client.valid());
    ASSERT_TRUE(client.send_hello());
    daemon.services.stats.user("alice")->set_quota_used_bytes(1000);
    EXPECT_TRUE(client.wait_closed_for(4000));
}

TEST(RuntimePolicy, UniqueIpLimitAllowsSameIpRejectsNewIpAndFreesSlotOnClose) {
    Daemon daemon(1, false);
    mtdd::control::UserPolicy policy;
    policy.max_unique_ips = 1;
    ASSERT_TRUE(add_policy_user(daemon, policy));

    TestClient first(daemon.port(), secret_bytes());
    ASSERT_TRUE(first.valid());
    ASSERT_TRUE(first.send_hello());
    // A second connection from the same address does not add a unique IP.
    TestClient same(daemon.port(), secret_bytes());
    ASSERT_TRUE(same.valid());
    EXPECT_TRUE(same.send_hello(0, 1));
    EXPECT_EQ(rejected(daemon, "user_ip_limit"), 0U);

    const int other_fd = connect_from("127.0.0.2", daemon.port());
    ASSERT_GE(other_fd, 0) << "127.0.0.2 is not usable as a source address here";
    TestClient other(TestClient::Adopt{}, other_fd, secret_bytes());
    EXPECT_FALSE(other.send_hello(0, 2));
    EXPECT_TRUE(wait_for([&] { return rejected(daemon, "user_ip_limit") >= 1U; }, 2s));
    EXPECT_EQ(rejected(daemon, "overload"), 0U);
    EXPECT_EQ(daemon.services.stats.snapshot().users.at("alice").active_connections, 2U);

    // The slot is freed once every connection of the first address is gone.
    first.close();
    same.close();
    ASSERT_TRUE(wait_for([&] {
        return daemon.services.stats.user("alice")->active_unique_ips() == 0;
    }, 3s));
    const int retry_fd = connect_from("127.0.0.2", daemon.port());
    ASSERT_GE(retry_fd, 0);
    TestClient retry(TestClient::Adopt{}, retry_fd, secret_bytes());
    EXPECT_TRUE(retry.send_hello(0, 3));
}

namespace {

// Pushes padded-intermediate frames to a fake DC (which echoes them back) while
// a second thread drains the echo, so neither direction stalls on the client.
class Pump {
public:
    Pump(TestClient& client, std::size_t total_bytes) : client_(client) {
        drain_ = std::thread([this] {
            std::array<std::uint8_t, 65536> sink{};
            while (!stop_.load()) {
                const ssize_t got = ::recv(client_.fd(), sink.data(), sink.size(), 0);
                if (got == 0) break;
                if (got < 0 && errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK) break;
            }
        });
        send_ = std::thread([this, total_bytes] {
            const Bytes payload(4092, 0x5a);
            std::size_t sent = 0;
            while (!stop_.load() && (total_bytes == 0 || sent < total_bytes)) {
                if (!client_.send_message(payload)) break;
                sent += payload.size() + 4;
            }
        });
    }
    ~Pump() {
        stop_.store(true);
        if (send_.joinable()) send_.join();
        client_.close();
        if (drain_.joinable()) drain_.join();
    }

private:
    TestClient& client_;
    std::atomic<bool> stop_{false};
    std::thread send_;
    std::thread drain_;
};

// Bytes per second moved by `counter` between two instants.
template <class Counter>
double measure(Counter&& counter, std::chrono::milliseconds warmup,
               std::chrono::milliseconds window) {
    std::this_thread::sleep_for(warmup);
    const auto t0 = std::chrono::steady_clock::now();
    const std::uint64_t a = counter();
    std::this_thread::sleep_for(window);
    const auto t1 = std::chrono::steady_clock::now();
    const std::uint64_t b = counter();
    return static_cast<double>(b - a) / std::chrono::duration<double>(t1 - t0).count();
}

} // namespace

TEST(RuntimePolicy, UpstreamRateLimitHoldsThroughputWithinTenPercent) {
    mtdd::test::FakeDirectDc dc(2);
    PolicyDirectEndpointScope endpoint(dc.port());
    Daemon daemon(1, true, [](mtdd::Config& config) { enable_policy_direct(config); });
    constexpr std::uint64_t kRate = 512 * 1024;
    mtdd::control::UserPolicy policy;
    policy.rate_limit_up_bytes_per_sec = kRate;
    ASSERT_TRUE(add_policy_user(daemon, policy));
    ASSERT_TRUE(wait_for([&] { return daemon.services.metadata->snapshot() != nullptr; }, 3s));

    TestClient client(daemon.port(), secret_bytes());
    ASSERT_TRUE(client.valid());
    ASSERT_TRUE(client.send_hello());
    ASSERT_TRUE(client.start_obfuscation(2));
    const auto metrics = daemon.services.stats.user("alice");
    Pump pump(client, 0);
    // The first second of data rides the burst allowance; measure afterwards.
    const double rate = measure([&] { return metrics->payload_c2s_bytes(); }, 1600ms, 2000ms);
    EXPECT_GT(rate, kRate * 0.9) << rate;
    EXPECT_LT(rate, kRate * 1.1) << rate;
}

TEST(RuntimePolicy, DownstreamRateLimitHoldsThroughputWithinTenPercent) {
    mtdd::test::FakeDirectDc dc(2);
    std::vector<std::vector<std::uint8_t>> frames(1536, std::vector<std::uint8_t>(4092, 0x33));
    dc.send_unsolicited(std::move(frames));  // 6 MiB queued towards the client
    PolicyDirectEndpointScope endpoint(dc.port());
    Daemon daemon(1, true, [](mtdd::Config& config) { enable_policy_direct(config); });
    constexpr std::uint64_t kRate = 512 * 1024;
    mtdd::control::UserPolicy policy;
    policy.rate_limit_down_bytes_per_sec = kRate;
    ASSERT_TRUE(add_policy_user(daemon, policy));
    ASSERT_TRUE(wait_for([&] { return daemon.services.metadata->snapshot() != nullptr; }, 3s));

    TestClient client(daemon.port(), secret_bytes());
    ASSERT_TRUE(client.valid());
    ASSERT_TRUE(client.send_hello());
    ASSERT_TRUE(client.start_obfuscation(2));
    const auto metrics = daemon.services.stats.user("alice");
    Pump pump(client, 4096);  // one frame only: opens the route, then idles
    const double rate = measure([&] { return metrics->payload_s2c_bytes(); }, 1600ms, 2000ms);
    EXPECT_GT(rate, kRate * 0.9) << rate;
    EXPECT_LT(rate, kRate * 1.1) << rate;
}

TEST(RuntimePolicy, RateLimitChangeAppliesToLiveSessions) {
    mtdd::test::FakeDirectDc dc(2);
    PolicyDirectEndpointScope endpoint(dc.port());
    Daemon daemon(1, true, [](mtdd::Config& config) { enable_policy_direct(config); });
    mtdd::control::UserPolicy policy;
    policy.rate_limit_up_bytes_per_sec = 256 * 1024;
    ASSERT_TRUE(add_policy_user(daemon, policy));
    ASSERT_TRUE(wait_for([&] { return daemon.services.metadata->snapshot() != nullptr; }, 3s));

    TestClient client(daemon.port(), secret_bytes());
    ASSERT_TRUE(client.valid());
    ASSERT_TRUE(client.send_hello());
    ASSERT_TRUE(client.start_obfuscation(2));
    const auto metrics = daemon.services.stats.user("alice");
    Pump pump(client, 0);
    const double slow = measure([&] { return metrics->payload_c2s_bytes(); }, 1600ms, 1500ms);
    EXPECT_LT(slow, 256 * 1024 * 1.2) << slow;

    mtdd::control::UserPolicyPatch patch;
    patch.rate_limit_up_bytes_per_sec = std::optional<std::uint64_t>(2 * 1024 * 1024);
    ASSERT_TRUE(patch_policy(daemon, patch));
    const double fast = measure([&] { return metrics->payload_c2s_bytes(); }, 600ms, 1500ms);
    EXPECT_GT(fast, slow * 2.5) << "slow=" << slow << " fast=" << fast;
}

TEST(RuntimePolicy, UnlimitedUserIsNotThrottled) {
    mtdd::test::FakeDirectDc dc(2);
    PolicyDirectEndpointScope endpoint(dc.port());
    Daemon daemon(1, true, [](mtdd::Config& config) { enable_policy_direct(config); });
    ASSERT_TRUE(add_policy_user(daemon, {}));
    ASSERT_TRUE(wait_for([&] { return daemon.services.metadata->snapshot() != nullptr; }, 3s));

    TestClient client(daemon.port(), secret_bytes());
    ASSERT_TRUE(client.valid());
    ASSERT_TRUE(client.send_hello());
    ASSERT_TRUE(client.start_obfuscation(2));
    const auto metrics = daemon.services.stats.user("alice");
    constexpr std::uint64_t kTotal = 4U << 20;
    Pump pump(client, kTotal);
    // A 512 KiB/s limit would need about seven seconds for this volume.
    EXPECT_TRUE(wait_for([&] { return metrics->payload_c2s_bytes() >= kTotal; }, 3500ms))
        << metrics->payload_c2s_bytes();
}
