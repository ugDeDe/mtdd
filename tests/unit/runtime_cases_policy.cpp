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

namespace {

// An MTProto message whose first 8 bytes carry `auth_key_id` (little endian).
Bytes keyed_message(std::uint64_t auth_key_id) {
    Bytes payload(64, 0x11);
    for (std::size_t i = 0; i < 8; ++i) {
        payload[i] = static_cast<std::uint8_t>(auth_key_id >> (8 * i));
    }
    return payload;
}

std::uint64_t device_limit_closes(Daemon& daemon) {
    return daemon.services.stats.snapshot().relay_closes_total[static_cast<std::size_t>(
        mtdd::control::RelayCloseReason::device_limit)];
}

} // namespace

TEST(RuntimePolicy, DeviceLimitAdmitsKnownKeyAndClosesNewKeyOverLimit) {
    mtdd::test::FakeDirectDc dc(2);
    PolicyDirectEndpointScope endpoint(dc.port());
    Daemon daemon(1, true, [](mtdd::Config& config) { enable_policy_direct(config); });
    mtdd::control::UserPolicy policy;
    policy.max_devices = 1;
    ASSERT_TRUE(add_policy_user(daemon, policy));
    ASSERT_TRUE(wait_for([&] { return daemon.services.metadata->snapshot() != nullptr; }, 3s));
    const auto metrics = daemon.services.stats.user("alice");

    TestClient first(daemon.port(), secret_bytes());
    ASSERT_TRUE(first.valid());
    ASSERT_TRUE(first.send_hello());
    ASSERT_TRUE(first.start_obfuscation(2));
    // Key exchange (auth_key_id 0) is not a device.
    ASSERT_TRUE(first.send_message(keyed_message(0)));
    ASSERT_TRUE(first.send_message(keyed_message(0x1111)));
    ASSERT_TRUE(wait_for([&] { return metrics->devices() == 1U; }, 3s));

    // The same key on another connection is the same device.
    TestClient same(daemon.port(), secret_bytes());
    ASSERT_TRUE(same.valid());
    ASSERT_TRUE(same.send_hello(0, 1));
    ASSERT_TRUE(same.start_obfuscation(2));
    ASSERT_TRUE(same.send_message(keyed_message(0x1111)));

    TestClient other(daemon.port(), secret_bytes());
    ASSERT_TRUE(other.valid());
    ASSERT_TRUE(other.send_hello(0, 2));
    ASSERT_TRUE(other.start_obfuscation(2));
    ASSERT_TRUE(other.send_message(keyed_message(0x2222)));
    EXPECT_TRUE(other.wait_closed_for(3000));
    EXPECT_EQ(device_limit_closes(daemon), 1U);
    EXPECT_EQ(metrics->devices(), 1U);
    EXPECT_FALSE(first.wait_closed_for(200));
    EXPECT_FALSE(same.wait_closed_for(200));
}

TEST(RuntimePolicy, DisconnectedDeviceFreesItsSlotForANewOne) {
    mtdd::test::FakeDirectDc dc(2);
    PolicyDirectEndpointScope endpoint(dc.port());
    Daemon daemon(1, true, [](mtdd::Config& config) { enable_policy_direct(config); });
    mtdd::control::UserPolicy policy;
    policy.max_devices = 1;
    ASSERT_TRUE(add_policy_user(daemon, policy));
    ASSERT_TRUE(wait_for([&] { return daemon.services.metadata->snapshot() != nullptr; }, 3s));
    const auto metrics = daemon.services.stats.user("alice");
    {
        TestClient first(daemon.port(), secret_bytes());
        ASSERT_TRUE(first.valid());
        ASSERT_TRUE(first.send_hello());
        ASSERT_TRUE(first.start_obfuscation(2));
        ASSERT_TRUE(first.send_message(keyed_message(0x1111)));
        ASSERT_TRUE(wait_for([&] { return metrics->devices() == 1U; }, 3s));
        EXPECT_EQ(metrics->devices_connected(), 1U);
        const auto listed = daemon.services.stats.devices("alice");
        ASSERT_EQ(listed.size(), 1U);
        EXPECT_EQ(listed[0].dc, 2);
        EXPECT_EQ(listed[0].connections, 1U);
        EXPECT_EQ(listed[0].ip, "127.0.0.1");
    }
    ASSERT_TRUE(wait_for([&] {
        return daemon.services.stats.snapshot().users.at("alice").active_connections == 0U;
    }, 3s));
    EXPECT_EQ(metrics->devices_connected(), 0U);
    EXPECT_EQ(metrics->devices(), 1U);  // still listed within the window
    // The first device is gone: a new one takes its slot immediately.
    TestClient second(daemon.port(), secret_bytes());
    ASSERT_TRUE(second.valid());
    ASSERT_TRUE(second.send_hello(0, 1));
    ASSERT_TRUE(second.start_obfuscation(2));
    ASSERT_TRUE(second.send_message(keyed_message(0x2222)));
    EXPECT_FALSE(second.wait_closed_for(500));
    EXPECT_EQ(device_limit_closes(daemon), 0U);
    // The displaced first device is now the new one, and is held off.
    TestClient back(daemon.port(), secret_bytes());
    ASSERT_TRUE(back.valid());
    ASSERT_TRUE(back.send_hello(0, 2));
    ASSERT_TRUE(back.start_obfuscation(2));
    ASSERT_TRUE(back.send_message(keyed_message(0x1111)));
    EXPECT_TRUE(back.wait_closed_for(3000));
    // Raising the limit admits it.
    mtdd::control::UserPolicyPatch patch;
    patch.max_devices = std::optional<std::uint32_t>(2);
    ASSERT_TRUE(patch_policy(daemon, patch));
    TestClient again(daemon.port(), secret_bytes());
    ASSERT_TRUE(again.valid());
    ASSERT_TRUE(again.send_hello(0, 3));
    ASSERT_TRUE(again.start_obfuscation(2));
    ASSERT_TRUE(again.send_message(keyed_message(0x1111)));
    EXPECT_FALSE(again.wait_closed_for(500));
    EXPECT_TRUE(wait_for([&] { return metrics->devices() == 2U; }, 3s));
}

TEST(DeviceTable, CountsPerSignedDcAndDisplacesOnlyIdleKeys) {
    mtdd::detail::DeviceTable table;
    const auto t0 = std::chrono::steady_clock::now();
    mtdd::detail::DeviceTable::Count devices;
    using Admit = mtdd::detail::DeviceTable::Admit;
    const auto peer = mtdd::protocol::Endpoint::v4({10, 0, 0, 7}, 4000);
    constexpr auto kPlatform = mtdd::detail::Platform::android;
    EXPECT_EQ(table.admit("u", 2, 1, peer, kPlatform, 1, t0, 60s, devices), Admit::ok);
    // A media DC key is counted on its own DC, not as a second device.
    EXPECT_EQ(table.admit("u", -2, 7, peer, kPlatform, 1, t0, 60s, devices), Admit::ok);
    EXPECT_EQ(devices.recent, 1U);
    // Key 1 has an open connection: key 2 is held off.
    EXPECT_EQ(table.admit("u", 2, 2, peer, kPlatform, 1, t0, 60s, devices), Admit::limit);
    table.release("u", 2, 1, t0, 60s, devices);
    const auto listed = table.list("u", t0 + 5s, 60s);
    ASSERT_EQ(listed.size(), 2U);
    for (const auto& device : listed) {
        EXPECT_EQ(device.ip, "10.0.0.7");
        EXPECT_EQ(device.platform, "Android");
        EXPECT_EQ(device.connections, device.dc == 2 ? 0U : 1U);
        EXPECT_EQ(device.idle_seconds, device.dc == 2 ? 5 : 0);
    }
    EXPECT_EQ(devices.recent, 1U);  // still listed within the window
    EXPECT_EQ(devices.connected, 1U);  // the media key is still open
    // Idle key 1 gives way at once.
    EXPECT_EQ(table.admit("u", 2, 2, peer, kPlatform, 1, t0 + 1s, 60s, devices), Admit::ok);
    EXPECT_EQ(devices.recent, 1U);
    EXPECT_EQ(table.admit("u", 2, 1, peer, kPlatform, 1, t0 + 2s, 60s, devices), Admit::limit);
    std::vector<std::pair<std::string, mtdd::detail::DeviceTable::Count>> counts;
    table.release("u", 2, 2, t0 + 2s, 60s, devices);
    table.release("u", -2, 7, t0 + 2s, 60s, devices);
    table.prune(t0 + 200s, 60s, counts);
    ASSERT_EQ(counts.size(), 1U);
    EXPECT_EQ(counts[0].second.recent, 0U);
    EXPECT_EQ(counts[0].second.connected, 0U);
    table.prune(t0 + 200s, 60s, counts);
    EXPECT_TRUE(counts.empty());
}

namespace {

// IPv4 + TCP SYN header bytes as TCP_SAVED_SYN returns them.
Bytes saved_syn(std::uint8_t ttl, std::uint16_t window, const Bytes& options) {
    Bytes syn(20, 0);
    syn[0] = 0x45;
    syn[8] = ttl;
    syn[9] = 6;
    Bytes tcp(20, 0);
    const std::size_t padded = (options.size() + 3) / 4 * 4;
    tcp[12] = static_cast<std::uint8_t>(((20 + padded) / 4) << 4);
    tcp[13] = 0x02;
    tcp[14] = static_cast<std::uint8_t>(window >> 8);
    tcp[15] = static_cast<std::uint8_t>(window);
    syn.insert(syn.end(), tcp.begin(), tcp.end());
    syn.insert(syn.end(), options.begin(), options.end());
    syn.resize(20 + 20 + padded, 0);
    return syn;
}

const Bytes kTs{8, 10, 1, 2, 3, 4, 0, 0, 0, 0};
Bytes concat(std::initializer_list<Bytes> parts) {
    Bytes out;
    for (const auto& part : parts) out.insert(out.end(), part.begin(), part.end());
    return out;
}
const Bytes kAppleSyn = saved_syn(53, 65535, concat({{2, 4, 0x05, 0xb4, 1, 3, 3, 6, 1, 1}, kTs, {4, 2, 0}}));
const Bytes kLinuxSyn = saved_syn(57, 64240, concat({{2, 4, 0x05, 0xb4, 4, 2}, kTs, {1, 3, 3, 7}}));
const Bytes kAndroidSyn = saved_syn(55, 65535, concat({{2, 4, 0x05, 0xac, 4, 2}, kTs, {1, 3, 3, 9}}));
const Bytes kWindowsSyn = saved_syn(117, 65535, {2, 4, 0x05, 0x9c, 1, 3, 3, 8, 1, 1, 4, 2});
const Bytes kScannerSyn = saved_syn(236, 1024, {});
// Seen in the field: Windows with timestamps, Windows with TTL rewritten to
// 64 (tethering), and Android behind a box that replaced timestamps with NOPs.
const Bytes kWindowsTsSyn = saved_syn(119, 65535, concat({{2, 4, 0x05, 0xac, 1, 3, 3, 8, 4, 2}, kTs}));
const Bytes kWindowsTtl64Syn = saved_syn(55, 64240, {2, 4, 0x05, 0xb4, 1, 3, 3, 8, 1, 1, 4, 2});
const Bytes kAndroidNoTsSyn = saved_syn(
    54, 65535, {2, 4, 0x05, 0x50, 4, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 3, 3, 10});

// A ClientHello record with the given extension types (empty bodies).
Bytes client_hello(std::initializer_list<std::uint16_t> extensions) {
    Bytes body{0x03, 0x03};
    body.resize(2 + 32, 0x11);
    body.push_back(0);                       // session id
    body.insert(body.end(), {0, 2, 0x13, 0x01});  // one cipher suite
    body.insert(body.end(), {1, 0});         // compression
    Bytes ext;
    for (const auto type : extensions) {
        ext.insert(ext.end(), {static_cast<std::uint8_t>(type >> 8),
                               static_cast<std::uint8_t>(type), 0, 0});
    }
    body.push_back(static_cast<std::uint8_t>(ext.size() >> 8));
    body.push_back(static_cast<std::uint8_t>(ext.size()));
    body.insert(body.end(), ext.begin(), ext.end());
    Bytes record{0x16, 0x03, 0x01, 0, 0, 0x01, 0, 0, 0};
    const std::size_t hs = body.size();
    record[3] = static_cast<std::uint8_t>((hs + 4) >> 8);
    record[4] = static_cast<std::uint8_t>(hs + 4);
    record[7] = static_cast<std::uint8_t>(hs >> 8);
    record[8] = static_cast<std::uint8_t>(hs);
    record.insert(record.end(), body.begin(), body.end());
    return record;
}

const Bytes kSafariHello = client_hello(
    {0x0a0a, 0, 23, 65281, 10, 11, 16, 5, 13, 18, 51, 45, 43, 27, 0x1a1a});
const Bytes kChromeHello = client_hello(
    {0x2a2a, 65281, 51, 17613, 45, 11, 10, 27, 16, 43, 18, 5, 13, 0, 35, 23, 65037, 0x3a3a});
const Bytes kGoHello = client_hello({5, 10, 11, 13, 65281, 23, 18, 43, 51});

mtdd::detail::Platform platform_of(const Bytes& syn, const Bytes& hello) {
    return mtdd::detail::classify_platform(mtdd::detail::parse_saved_syn(syn),
                                           mtdd::detail::classify_client_hello(hello));
}

} // namespace

TEST(Platform, ReferenceFingerprintsClassify) {
    using mtdd::detail::Platform;
    EXPECT_EQ(platform_of(kAppleSyn, kSafariHello), Platform::apple);
    EXPECT_EQ(platform_of(kAndroidSyn, kSafariHello), Platform::apple);  // TLS decides
    EXPECT_EQ(platform_of(kLinuxSyn, kChromeHello), Platform::linux_desktop);
    EXPECT_EQ(platform_of(kAndroidSyn, kChromeHello), Platform::android);
    EXPECT_EQ(platform_of(kWindowsSyn, kChromeHello), Platform::windows);
    EXPECT_EQ(platform_of(kAppleSyn, kChromeHello), Platform::apple);  // macOS Desktop
    EXPECT_EQ(platform_of(kScannerSyn, kChromeHello), Platform::undefined);
    EXPECT_EQ(platform_of(kWindowsTsSyn, kChromeHello), Platform::windows);
    EXPECT_EQ(platform_of(kWindowsTtl64Syn, kChromeHello), Platform::windows);
    EXPECT_EQ(platform_of(kAndroidNoTsSyn, kChromeHello), Platform::android);
    // Android with its TTL rewritten to 128.
    EXPECT_EQ(platform_of(saved_syn(115, 65535, concat({{2, 4, 0x05, 0xb4, 4, 2}, kTs, {1, 3, 3, 9}})),
                          kChromeHello),
              Platform::android);
    EXPECT_EQ(platform_of(kLinuxSyn, kGoHello), Platform::undefined);
    EXPECT_EQ(platform_of({}, kChromeHello), Platform::undefined);
    const auto syn = mtdd::detail::parse_saved_syn(kWindowsSyn);
    EXPECT_EQ(syn.ttl, 117);
    EXPECT_EQ(syn.wscale, 8);
    EXPECT_EQ(syn.mss, 1436);
    EXPECT_FALSE(syn.timestamps);
    EXPECT_STREQ(mtdd::detail::platform_name(Platform::undefined), "Undefined");
}

TEST(Platform, TruncatedInputIsUndefinedNotACrash) {
    for (std::size_t cut = 0; cut < kChromeHello.size(); ++cut) {
        const Bytes part(kChromeHello.begin(), kChromeHello.begin() + static_cast<long>(cut));
        (void)mtdd::detail::classify_client_hello(part);
    }
    for (std::size_t cut = 0; cut < kAppleSyn.size(); ++cut) {
        const Bytes part(kAppleSyn.begin(), kAppleSyn.begin() + static_cast<long>(cut));
        (void)mtdd::detail::parse_saved_syn(part);
    }
    Bytes bogus = kAppleSyn;
    bogus[20 + 12] = 0xf0;  // data offset beyond the buffer
    (void)mtdd::detail::parse_saved_syn(bogus);
}

TEST(Watch, NetworkParsingAndMatching) {
    using mtdd::detail::parse_watch_net;
    using mtdd::detail::watch_net_contains;
    const auto host = parse_watch_net("2.63.211.145");
    ASSERT_TRUE(host);
    EXPECT_TRUE(watch_net_contains(*host, mtdd::protocol::Endpoint::v4({2, 63, 211, 145}, 1)));
    EXPECT_FALSE(watch_net_contains(*host, mtdd::protocol::Endpoint::v4({2, 63, 211, 146}, 1)));
    const auto net = parse_watch_net("185.104.251.0/24");
    ASSERT_TRUE(net);
    EXPECT_TRUE(watch_net_contains(*net, mtdd::protocol::Endpoint::v4({185, 104, 251, 54}, 1)));
    EXPECT_FALSE(watch_net_contains(*net, mtdd::protocol::Endpoint::v4({185, 104, 252, 54}, 1)));
    const auto v6 = parse_watch_net("2001:db8::/32");
    ASSERT_TRUE(v6);
    std::array<std::uint8_t, 16> address{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
    EXPECT_TRUE(watch_net_contains(*v6, mtdd::protocol::Endpoint::v6(address, 1)));
    EXPECT_FALSE(watch_net_contains(*v6, mtdd::protocol::Endpoint::v4({32, 1, 13, 184}, 1)));
    for (const char* bad : {"", "1.2.3.4/33", "::/129", "host.example", "1.2.3.4/x"}) {
        EXPECT_FALSE(parse_watch_net(bad)) << bad;
    }
}

TEST(Watch, LogsEveryStageOfAWatchedConnection) {
    mtdd::test::FakeDirectDc dc(2);
    PolicyDirectEndpointScope endpoint(dc.port());
    testing::internal::CaptureStderr();
    {
        Daemon daemon(1, true, [](mtdd::Config& config) {
            enable_policy_direct(config);
            config.watch_ips = {"127.0.0.1"};
        });
        mtdd::control::UserPolicy policy;
        ASSERT_TRUE(add_policy_user(daemon, policy));
        ASSERT_TRUE(wait_for([&] { return daemon.services.metadata->snapshot() != nullptr; }, 3s));
        {
            TestClient client(daemon.port(), secret_bytes());
            ASSERT_TRUE(client.valid());
            ASSERT_TRUE(client.send_hello());
            ASSERT_TRUE(client.start_obfuscation(2));
            ASSERT_TRUE(client.send_message(keyed_message(0)));
            ASSERT_TRUE(client.send_message(keyed_message(0x1111)));
            ASSERT_TRUE(wait_for([&] {
                return daemon.services.stats.user("alice")->devices() == 1U;
            }, 3s));
        }
        {
            TestClient probe(daemon.port(), secret_bytes());
            ASSERT_TRUE(probe.valid());
            const std::string get = "GET / HTTP/1.1\r\nHost: x\r\n\r\n";
            ASSERT_EQ(::send(probe.fd(), get.data(), get.size(), MSG_NOSIGNAL),
                      static_cast<ssize_t>(get.size()));
            EXPECT_TRUE(probe.wait_closed_for(3000));
        }
        // Not watched: no log lines for 127.0.0.2.
        const int other_fd = connect_from("127.0.0.2", daemon.port());
        ASSERT_GE(other_fd, 0);
        TestClient other(TestClient::Adopt{}, other_fd, secret_bytes());
        EXPECT_TRUE(other.send_hello(0, 1));
        ASSERT_TRUE(wait_for([&] {
            return daemon.services.stats.snapshot().users.at("alice").active_connections <= 1U;
        }, 3s));
    }
    const std::string log = testing::internal::GetCapturedStderr();
    for (const char* text :
         {"mtdd watch: conn=", " accept syn=", " hello bytes=", "tls=other", " auth result=ok user=alice",
          " tls_ready dc=2 proto=secure route=direct", " frame len=", "auth_key_id=0000000000000000",
          " device auth_key_id=0000000000001111 dc=2", "result=ok", " close phase=relay",
          " rx=", " first_bytes bytes=", "not_tls", "text=GET./.HTTP/1.1"}) {
        EXPECT_NE(log.find(text), std::string::npos) << text << "\n" << log;
    }
    EXPECT_EQ(log.find("peer=127.0.0.2"), std::string::npos) << log;
}

// ---------------------------------------------------------------------------
// Suspicious-behaviour detection
// ---------------------------------------------------------------------------

namespace {

using mtdd::control::SuspectSignal;

mtdd::detail::SuspectTable::Context suspect_context(const mtdd::protocol::Endpoint& peer) {
    mtdd::detail::SuspectTable::Context context;
    context.peer = &peer;
    return context;
}

std::uint32_t suspect_hits(const mtdd::control::Statistics::SuspectInfo& info, SuspectSignal signal) {
    return info.hits[static_cast<std::size_t>(signal)];
}

const mtdd::control::Statistics::SuspectInfo* find_suspect(
    const std::vector<mtdd::control::Statistics::SuspectInfo>& rows, const std::string& ip) {
    for (const auto& row : rows) {
        if (row.ip == ip) return &row;
    }
    return nullptr;
}

} // namespace

TEST(Suspects, RawProbeClassification) {
    using mtdd::detail::RawProbe;
    using mtdd::detail::classify_raw_probe;
    const std::string secret = "eedddddddddddddddddddddddddddddddd6d2e6265626f6f2e7275";
    EXPECT_EQ(classify_raw_probe(Bytes(secret.begin(), secret.end())), RawProbe::secret_text);
    const std::string dd = "dd0123456789abcdef0123456789abcdef";
    EXPECT_EQ(classify_raw_probe(Bytes(dd.begin(), dd.end())), RawProbe::secret_text);
    Bytes random(96);
    for (std::size_t i = 0; i < random.size(); ++i) {
        random[i] = static_cast<std::uint8_t>((i * 167U + 13U) ^ (i * i));
    }
    EXPECT_EQ(classify_raw_probe(random), RawProbe::raw_obfuscated2);
    const std::string http = "GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: curl/8\r\nAccept: */*\r\n\r\n";
    EXPECT_EQ(classify_raw_probe(Bytes(http.begin(), http.end())), RawProbe::junk);
    EXPECT_EQ(classify_raw_probe(Bytes{0x05, 0x01, 0x00}), RawProbe::junk);
    EXPECT_TRUE(mtdd::detail::domain_covers("M.Beboo.ru.", "m.beboo.ru"));
    EXPECT_TRUE(mtdd::detail::domain_covers("cdn.m.beboo.ru", "m.beboo.ru"));
    EXPECT_FALSE(mtdd::detail::domain_covers("evilm.beboo.ru", "m.beboo.ru"));
}

TEST(Suspects, ScoreWeightsRepeatsDecayAndMatches) {
    using Table = mtdd::detail::SuspectTable;
    std::array<std::uint32_t, mtdd::control::kSuspectSignals> hits{};
    hits[static_cast<std::size_t>(SuspectSignal::port_check)] = 1;
    EXPECT_DOUBLE_EQ(Table::score_of(hits, 0), 10.0);
    hits[static_cast<std::size_t>(SuspectSignal::port_check)] = 3;  // +2 repeats
    EXPECT_DOUBLE_EQ(Table::score_of(hits, 0), 15.0);
    hits[static_cast<std::size_t>(SuspectSignal::port_check)] = 50;  // capped at double
    EXPECT_DOUBLE_EQ(Table::score_of(hits, 0), 20.0);
    EXPECT_DOUBLE_EQ(Table::score_of(hits, 24), 10.0);  // half-life 24 h
    hits[static_cast<std::size_t>(SuspectSignal::canary)] = 9;
    hits[static_cast<std::size_t>(SuspectSignal::probe_session)] = 1;
    EXPECT_DOUBLE_EQ(Table::score_of(hits, 0), 100.0);  // capped

    Table table(256);
    const auto now = std::chrono::steady_clock::now();
    const auto peer = mtdd::protocol::Endpoint::v4({203, 0, 113, 7}, 5000);
    auto first = table.record(suspect_context(peer), SuspectSignal::junk, now, 1000, 60);
    EXPECT_EQ(first.matches, 1U);
    EXPECT_FALSE(first.crossed_watch);
    table.record(suspect_context(peer), SuspectSignal::port_check, now, 1001, 60);
    auto crossed = table.record(suspect_context(peer), SuspectSignal::probe_session, now, 1002, 50);
    EXPECT_EQ(crossed.matches, 3U);
    EXPECT_TRUE(crossed.crossed_watch);
    EXPECT_EQ(crossed.signals, "probe_session,port_check,junk");
    EXPECT_FALSE(table.record(suspect_context(peer), SuspectSignal::junk, now, 1003, 50).crossed_watch);
    // Another port of the same address is the same suspect.
    const auto same = mtdd::protocol::Endpoint::v4({203, 0, 113, 7}, 6000);
    EXPECT_GT(table.score(same, now), 50.0);
    const auto rows = table.list(now, 1004, 50, 0);
    ASSERT_EQ(rows.size(), 1U);
    EXPECT_EQ(rows[0].ip, "203.0.113.7");
    EXPECT_EQ(suspect_hits(rows[0], SuspectSignal::junk), 2U);
    EXPECT_TRUE(rows[0].watched);
    EXPECT_FALSE(rows[0].shadow_banned);
    EXPECT_EQ(rows[0].first_seen, 1000);
    EXPECT_EQ(rows[0].last_seen, 1003);
    table.prune(now + std::chrono::hours(200), std::chrono::hours(168));
    EXPECT_TRUE(table.list(now, 0, 0, 0).empty());
}

TEST(Suspects, VisitsMultiModeAndEviction) {
    using Table = mtdd::detail::SuspectTable;
    Table table(256);  // 16 shards x 16
    const auto t0 = std::chrono::steady_clock::now();
    const auto peer = mtdd::protocol::Endpoint::v4({198, 51, 100, 1}, 1);
    EXPECT_FALSE(table.accept(peer, t0).known);  // unknown address: no entry
    table.record(suspect_context(peer), SuspectSignal::secret_text, t0, 1, 60);
    EXPECT_FALSE(table.accept(peer, t0 + std::chrono::minutes(1)).repeat_visit);
    EXPECT_FALSE(table.accept(peer, t0 + std::chrono::minutes(10)).repeat_visit);  // visit 2
    const auto third = table.accept(peer, t0 + std::chrono::minutes(20));        // visit 3
    EXPECT_TRUE(third.known);
    EXPECT_TRUE(third.repeat_visit);
    // A long session clears the short-visit pattern.
    EXPECT_FALSE(table.close_session(peer, t0 + std::chrono::minutes(20),
                                     t0 + std::chrono::minutes(25)));
    EXPECT_FALSE(table.accept(peer, t0 + std::chrono::minutes(40)).repeat_visit);
    // D: raw obfuscated2 right around a FakeTLS session from the same address.
    const auto t1 = t0 + std::chrono::hours(1);
    table.record(suspect_context(peer), SuspectSignal::raw_obfuscated2, t1 + std::chrono::milliseconds(700), 2, 60);
    EXPECT_TRUE(table.close_session(peer, t1, t1 + std::chrono::milliseconds(2500)));
    EXPECT_FALSE(table.close_session(peer, t1 + std::chrono::seconds(30), t1 + std::chrono::seconds(31)));
    // Bounded: far more addresses than capacity keeps at most capacity entries.
    for (std::uint32_t i = 0; i < 1000; ++i) {
        const auto other = mtdd::protocol::Endpoint::v4(
            {10, static_cast<std::uint8_t>(i >> 8), static_cast<std::uint8_t>(i), 1}, 1);
        table.record(suspect_context(other), SuspectSignal::junk, t1, 3, 60);
    }
    EXPECT_LE(table.list(t1, 0, 0, 0).size(), 256U);
}

namespace {

struct SuspectMaskingScope {
    explicit SuspectMaskingScope(std::uint16_t port) {
        mtdd::detail::set_masking_endpoint_override(
            mtdd::detail::DirectEndpointOverride{"127.0.0.1", port});
    }
    ~SuspectMaskingScope() { mtdd::detail::set_masking_endpoint_override(std::nullopt); }
    SuspectMaskingScope(const SuspectMaskingScope&) = delete;
    SuspectMaskingScope& operator=(const SuspectMaskingScope&) = delete;
};

// Opens a raw connection, sends `bytes`, waits for the proxy to finish with it.
void send_raw_probe(std::uint16_t port, const Bytes& bytes) {
    const int fd = connect_loopback(port);
    ASSERT_GE(fd, 0);
    if (!bytes.empty()) {
        ASSERT_TRUE(send_all(fd, bytes));
    }
    std::this_thread::sleep_for(150ms);
    ::close(fd);
}

bool suspect_has(Daemon& daemon, SuspectSignal signal) {
    const auto rows = daemon.services.stats.suspects();
    const auto* row = find_suspect(rows, "127.0.0.1");
    return row != nullptr && suspect_hits(*row, signal) != 0;
}

Bytes random_header() {
    Bytes bytes(96);
    for (std::size_t i = 0; i < bytes.size(); ++i) {
        bytes[i] = static_cast<std::uint8_t>((i * 167U + 13U) ^ (i * i * 7U));
    }
    return bytes;
}

} // namespace

TEST(Suspects, SecretTextPortCheckAndJunkAreRecorded) {
    EchoBackend echo;
    SuspectMaskingScope masking(echo.port());
    Daemon daemon(1, false);
    const std::string secret = "eedddddddddddddddddddddddddddddddd6d2e6265626f6f2e7275";
    send_raw_probe(daemon.port(), Bytes(secret.begin(), secret.end()));
    EXPECT_TRUE(wait_for([&] { return suspect_has(daemon, SuspectSignal::secret_text); }, 3s));
    send_raw_probe(daemon.port(), {});
    EXPECT_TRUE(wait_for([&] { return suspect_has(daemon, SuspectSignal::port_check); }, 3s));
    const std::string http = "GET / HTTP/1.1\r\nHost: x\r\n\r\n";
    send_raw_probe(daemon.port(), Bytes(http.begin(), http.end()));
    EXPECT_TRUE(wait_for([&] { return suspect_has(daemon, SuspectSignal::junk); }, 3s));
    const auto rows = daemon.services.stats.suspects();
    const auto* row = find_suspect(rows, "127.0.0.1");
    ASSERT_NE(row, nullptr);
    EXPECT_EQ(row->matches, 3U);
    EXPECT_EQ(row->layout, "linux");  // loopback SYN, kept by TCP_SAVE_SYN
    const auto snapshot = daemon.services.stats.snapshot();
    EXPECT_GE(snapshot.suspect_events_total[static_cast<std::size_t>(SuspectSignal::secret_text)], 1U);
}

TEST(Suspects, ProbeSessionAndMultiModeFromOneAddress) {
    // A checker targets DC1 (never the RF auth DC) and mixes transports.
    mtdd::test::FakeDirectDc dc(1);
    PolicyDirectEndpointScope endpoint(dc.port());
    EchoBackend echo;
    SuspectMaskingScope masking(echo.port());
    Daemon daemon(1, true, [](mtdd::Config& config) {
        enable_policy_direct(config);
        config.direct_fallback_dcs = {1};
    });
    ASSERT_TRUE(add_policy_user(daemon, mtdd::control::UserPolicy{}));
    ASSERT_TRUE(wait_for([&] { return daemon.services.metadata->snapshot() != nullptr; }, 3s));
    {
        TestClient checker(daemon.port(), secret_bytes());
        ASSERT_TRUE(checker.valid());
        ASSERT_TRUE(checker.send_hello());
        ASSERT_TRUE(checker.start_obfuscation(1));
        // Raw obfuscated2 from the same address while the FakeTLS session is up.
        send_raw_probe(daemon.port(), random_header());
        ASSERT_TRUE(checker.send_message(keyed_message(0)));  // key exchange starts...
        std::this_thread::sleep_for(100ms);
    }                                                          // ...and the client leaves
    EXPECT_TRUE(wait_for([&] { return suspect_has(daemon, SuspectSignal::probe_session); }, 3s));
    EXPECT_TRUE(suspect_has(daemon, SuspectSignal::raw_obfuscated2));
    EXPECT_TRUE(wait_for([&] { return suspect_has(daemon, SuspectSignal::multi_mode); }, 3s));
    const auto rows = daemon.services.stats.suspects();
    const auto* row = find_suspect(rows, "127.0.0.1");
    ASSERT_NE(row, nullptr);
    EXPECT_EQ(row->user, "alice");
    EXPECT_GE(row->score, 60.0);

    // A real client brings a key: no probe_session for it.
    Daemon clean(1, true, [](mtdd::Config& config) { enable_policy_direct(config); });
    ASSERT_TRUE(add_policy_user(clean, mtdd::control::UserPolicy{}));
    ASSERT_TRUE(wait_for([&] { return clean.services.metadata->snapshot() != nullptr; }, 3s));
    {
        TestClient client(clean.port(), secret_bytes());
        ASSERT_TRUE(client.valid());
        ASSERT_TRUE(client.send_hello());
        ASSERT_TRUE(client.start_obfuscation(2));
        ASSERT_TRUE(client.send_message(keyed_message(0x1111)));
        ASSERT_TRUE(wait_for([&] { return clean.services.stats.user("alice")->devices() == 1U; }, 3s));
    }
    ASSERT_TRUE(wait_for([&] {
        return clean.services.stats.snapshot().users.at("alice").active_connections == 0U;
    }, 3s));
    EXPECT_TRUE(clean.services.stats.suspects().empty());
}

TEST(Suspects, CanaryUserThenShadowBanSendsValidSecretToMasking) {
    mtdd::test::FakeDirectDc dc(2);
    PolicyDirectEndpointScope endpoint(dc.port());
    EchoBackend echo;
    SuspectMaskingScope masking(echo.port());
    Daemon daemon(1, true, [](mtdd::Config& config) {
        enable_policy_direct(config);
        config.masking = true;
        config.suspect_ban_score = 50;
    });
    mtdd::control::UserPolicy policy;
    policy.canary = true;
    ASSERT_TRUE(add_policy_user(daemon, policy));
    ASSERT_TRUE(wait_for([&] { return daemon.services.metadata->snapshot() != nullptr; }, 3s));
    {
        TestClient bait(daemon.port(), secret_bytes());
        ASSERT_TRUE(bait.valid());
        ASSERT_TRUE(bait.send_hello());  // authenticates: the score was 0
    }
    ASSERT_TRUE(wait_for([&] { return suspect_has(daemon, SuspectSignal::canary); }, 3s));
    EXPECT_EQ(echo.accepted(), 0U);
    TestClient again(daemon.port(), secret_bytes());
    ASSERT_TRUE(again.valid());
    EXPECT_FALSE(again.send_hello(0, 1));  // the real site answers, not FakeTLS
    EXPECT_TRUE(wait_for([&] { return echo.accepted() >= 1U; }, 3s));
    EXPECT_GE(daemon.services.stats.snapshot().suspect_shadow_bans_total, 1U);
    const auto rows = daemon.services.stats.suspects();
    const auto* row = find_suspect(rows, "127.0.0.1");
    ASSERT_NE(row, nullptr);
    EXPECT_TRUE(row->shadow_banned);
}

TEST(Suspects, CrossingTheWatchScoreLogsAndDisabledDetectionRecordsNothing) {
    EchoBackend echo;
    SuspectMaskingScope masking(echo.port());
    const std::string secret = "eedddddddddddddddddddddddddddddddd6d2e6265626f6f2e7275";
    testing::internal::CaptureStderr();
    {
        Daemon daemon(1, false, [](mtdd::Config& config) { config.suspect_watch_score = 30; });
        send_raw_probe(daemon.port(), Bytes(secret.begin(), secret.end()));
        ASSERT_TRUE(wait_for([&] { return suspect_has(daemon, SuspectSignal::secret_text); }, 3s));
        // Known now: the next connection is logged stage by stage.
        send_raw_probe(daemon.port(), Bytes(secret.begin(), secret.end()));
        ASSERT_TRUE(wait_for([&] {
            const auto rows = daemon.services.stats.suspects();
            const auto* row = find_suspect(rows, "127.0.0.1");
            return row != nullptr && suspect_hits(*row, SuspectSignal::secret_text) >= 2U;
        }, 3s));
    }
    const std::string log = testing::internal::GetCapturedStderr();
    EXPECT_NE(log.find("mtdd suspect: ip=127.0.0.1 score=40 matches=1 signals=secret_text"),
              std::string::npos) << log;
    EXPECT_NE(log.find(" accept syn="), std::string::npos) << log;
    EXPECT_NE(log.find(" suspect signal=secret_text"), std::string::npos) << log;

    Daemon off(1, false, [](mtdd::Config& config) { config.suspects = false; });
    send_raw_probe(off.port(), Bytes(secret.begin(), secret.end()));
    std::this_thread::sleep_for(200ms);
    EXPECT_TRUE(off.services.stats.suspects().empty());
}

TEST(Suspects, RealClientsDoNotScoreAmbiguousSignals) {
    using Table = mtdd::detail::SuspectTable;
    std::array<std::uint32_t, mtdd::control::kSuspectSignals> hits{};
    hits[static_cast<std::size_t>(SuspectSignal::probe_session)] = 1;
    hits[static_cast<std::size_t>(SuspectSignal::port_check)] = 1;
    hits[static_cast<std::size_t>(SuspectSignal::multi_mode)] = 1;
    EXPECT_DOUBLE_EQ(Table::score_of(hits, 0, false), 100.0);  // 40 + 10 + 50
    EXPECT_DOUBLE_EQ(Table::score_of(hits, 0, true), 50.0);    // only D counts

    Table table(256);
    const auto t0 = std::chrono::steady_clock::now();
    const auto client = mtdd::protocol::Endpoint::v4({100, 64, 0, 1}, 1);
    table.mark_real(client, t0);
    EXPECT_TRUE(table.recently_real(client, t0 + std::chrono::minutes(59)));
    // Racing and proxy pings of a real client: no entry at all.
    table.record(suspect_context(client), SuspectSignal::probe_session, t0, 1, 60);
    table.record(suspect_context(client), SuspectSignal::port_check, t0, 1, 60);
    EXPECT_TRUE(table.list(t0, 1, 60, 0).empty());
    // B still counts.
    table.record(suspect_context(client), SuspectSignal::secret_text, t0, 1, 60);
    ASSERT_EQ(table.list(t0, 1, 60, 0).size(), 1U);
    // The mark expires; a checker that never brings a key is unaffected.
    EXPECT_FALSE(table.recently_real(client, t0 + std::chrono::minutes(62)));
    const auto checker = mtdd::protocol::Endpoint::v4({100, 64, 0, 2}, 1);
    EXPECT_FALSE(table.recently_real(checker, t0));
    table.record(suspect_context(checker), SuspectSignal::probe_session, t0, 1, 60);
    // A real session after the probe neutralises it too.
    const auto later = mtdd::protocol::Endpoint::v4({100, 64, 0, 3}, 1);
    table.record(suspect_context(later), SuspectSignal::probe_session, t0, 1, 60);
    table.mark_real(later, t0 + std::chrono::seconds(5));
    for (const auto& row : table.list(t0, 1, 60, 0)) {
        if (row.ip == "100.64.0.3") {
            EXPECT_TRUE(row.real_client);
            EXPECT_DOUBLE_EQ(row.score, 0.0);
        }
        if (row.ip == "100.64.0.2") {
            EXPECT_FALSE(row.real_client);
            EXPECT_DOUBLE_EQ(row.score, 40.0);
        }
    }
}

TEST(Suspects, WatchBudgetAndScoreAwareEviction) {
    using Table = mtdd::detail::SuspectTable;
    Table table(256);
    const auto t0 = std::chrono::steady_clock::now();
    std::uint32_t allowed = 0;
    for (int i = 0; i < 100; ++i) allowed += table.watch_budget(t0) ? 1U : 0U;
    EXPECT_EQ(allowed, Table::kWatchPerMinute);
    EXPECT_TRUE(table.watch_budget(t0 + std::chrono::minutes(1)));

    // A real suspect recorded first survives a flood of one-off junk.
    const auto suspect = mtdd::protocol::Endpoint::v4({192, 0, 2, 200}, 1);
    table.record(suspect_context(suspect), SuspectSignal::multi_mode, t0, 1, 60);
    for (std::uint32_t i = 0; i < 20000; ++i) {
        const auto junk = mtdd::protocol::Endpoint::v4(
            {10, static_cast<std::uint8_t>(i >> 16), static_cast<std::uint8_t>(i >> 8),
             static_cast<std::uint8_t>(i)}, 1);
        table.record(suspect_context(junk), SuspectSignal::junk, t0, 2, 60);
    }
    const auto rows = table.list(t0, 3, 60, 0);
    EXPECT_LE(rows.size(), 256U);
    EXPECT_NE(find_suspect(rows, "192.0.2.200"), nullptr);
}

TEST(Suspects, RealClientRacingConnectionsIsNotASuspect) {
    mtdd::test::FakeDirectDc dc(2);
    PolicyDirectEndpointScope endpoint(dc.port());
    Daemon daemon(1, true, [](mtdd::Config& config) { enable_policy_direct(config); });
    ASSERT_TRUE(add_policy_user(daemon, mtdd::control::UserPolicy{}));
    ASSERT_TRUE(wait_for([&] { return daemon.services.metadata->snapshot() != nullptr; }, 3s));
    TestClient winner(daemon.port(), secret_bytes());
    ASSERT_TRUE(winner.valid());
    ASSERT_TRUE(winner.send_hello());
    ASSERT_TRUE(winner.start_obfuscation(2));
    ASSERT_TRUE(winner.send_message(keyed_message(0x1111)));
    ASSERT_TRUE(wait_for([&] { return daemon.services.stats.user("alice")->devices() == 1U; }, 3s));
    {
        // The losing race connection: key exchange started, then dropped.
        TestClient loser(daemon.port(), secret_bytes());
        ASSERT_TRUE(loser.valid());
        ASSERT_TRUE(loser.send_hello(0, 1));
        ASSERT_TRUE(loser.start_obfuscation(2));
        ASSERT_TRUE(loser.send_message(keyed_message(0)));
        std::this_thread::sleep_for(100ms);
    }
    send_raw_probe(daemon.port(), {});  // and a proxy ping
    EXPECT_TRUE(wait_for([&] {
        return daemon.services.stats.snapshot()
                   .suspect_events_total[static_cast<std::size_t>(SuspectSignal::port_check)] >= 1U;
    }, 3s));
    // The race loser abandoned req_pq on DC2, which is the RF auth DC, so it is
    // not a probe_session at all; the proxy ping is real-filtered. No suspect.
    EXPECT_EQ(daemon.services.stats.snapshot()
                  .suspect_events_total[static_cast<std::size_t>(SuspectSignal::probe_session)], 0U);
    EXPECT_TRUE(daemon.services.stats.suspects().empty());
}

TEST(Suspects, NewClientKeyCreationClearsLosingRaceConnection) {
    // A brand-new client on DC1 (so probe_session can fire): every frame has
    // auth_key_id 0 during key creation, so register_device never fires. The
    // winning connection reaches req_DH_params, which must mark the address
    // real and clear the losing connection's probe_session, even though the
    // loser closed first.
    mtdd::test::FakeDirectDc dc(1);
    PolicyDirectEndpointScope endpoint(dc.port());
    Daemon daemon(1, true, [](mtdd::Config& config) {
        enable_policy_direct(config);
        config.direct_fallback_dcs = {1};
    });
    ASSERT_TRUE(add_policy_user(daemon, mtdd::control::UserPolicy{}));
    ASSERT_TRUE(wait_for([&] { return daemon.services.metadata->snapshot() != nullptr; }, 3s));

    // The losing race connection: req_pq only, then gone.
    {
        TestClient loser(daemon.port(), secret_bytes());
        ASSERT_TRUE(loser.valid());
        ASSERT_TRUE(loser.send_hello());
        ASSERT_TRUE(loser.start_obfuscation(1));
        ASSERT_TRUE(loser.send_message(keyed_message(0)));  // req_pq, auth_key_id 0
        std::this_thread::sleep_for(100ms);
    }
    EXPECT_TRUE(wait_for([&] {
        return daemon.services.stats.snapshot()
                   .suspect_events_total[static_cast<std::size_t>(SuspectSignal::probe_session)] >= 1U;
    }, 3s));
    // Flagged for now (the winner has not run yet).
    {
        const auto rows = daemon.services.stats.suspects();
        const auto* row = find_suspect(rows, "127.0.0.1");
        ASSERT_NE(row, nullptr);
        EXPECT_GT(row->score, 0.0);
    }
    // The winning connection reaches req_DH_params (still auth_key_id 0).
    {
        TestClient winner(daemon.port(), secret_bytes());
        ASSERT_TRUE(winner.valid());
        ASSERT_TRUE(winner.send_hello(0, 1));
        ASSERT_TRUE(winner.start_obfuscation(1));
        Bytes req_dh(64, 0x11);
        std::fill_n(req_dh.begin(), 8, std::uint8_t{0});  // auth_key_id 0
        req_dh[20] = 0xbe;                                 // req_DH_params, little endian
        req_dh[21] = 0xe4;
        req_dh[22] = 0x12;
        req_dh[23] = 0xd7;
        ASSERT_TRUE(winner.send_message(req_dh));
        std::this_thread::sleep_for(150ms);
    }
    // The address is now known real: probe_session scores nothing.
    EXPECT_TRUE(wait_for([&] {
        const auto rows = daemon.services.stats.suspects();
        const auto* row = find_suspect(rows, "127.0.0.1");
        return row != nullptr && row->real_client && row->score == 0.0;
    }, 3s));
}

TEST(Suspects, RealClientOnDc2ProbeIsNotFlagged) {
    // The RF auth DC is DC2: a client that does req_pq on DC2 and leaves (a
    // race loser) is never a probe_session, so it is never a suspect.
    mtdd::test::FakeDirectDc dc(2);
    PolicyDirectEndpointScope endpoint(dc.port());
    Daemon daemon(1, true, [](mtdd::Config& config) { enable_policy_direct(config); });
    ASSERT_TRUE(add_policy_user(daemon, mtdd::control::UserPolicy{}));
    ASSERT_TRUE(wait_for([&] { return daemon.services.metadata->snapshot() != nullptr; }, 3s));
    {
        TestClient loser(daemon.port(), secret_bytes());
        ASSERT_TRUE(loser.valid());
        ASSERT_TRUE(loser.send_hello());
        ASSERT_TRUE(loser.start_obfuscation(2));
        ASSERT_TRUE(loser.send_message(keyed_message(0)));
        std::this_thread::sleep_for(150ms);
    }
    std::this_thread::sleep_for(150ms);
    EXPECT_EQ(daemon.services.stats.snapshot()
                  .suspect_events_total[static_cast<std::size_t>(SuspectSignal::probe_session)], 0U);
    EXPECT_TRUE(daemon.services.stats.suspects().empty());
}
