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
