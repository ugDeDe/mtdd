#include "../support/runtime_fixture.hpp"

// ---------------------------------------------------------------------------
// Per-user payload accounting is batched per connection (detail::PayloadBatch):
// shared UserMetrics counters are written every 64 KiB, by the 1 Hz client
// pass, and on close, instead of once per frame.
// ---------------------------------------------------------------------------

namespace {

using mtdd::control::Direction;

constexpr std::uint64_t kAnswerBytes = 8;  // FakeMe's fixed answer payload

struct PayloadTotals {
    std::uint64_t c2s{0};
    std::uint64_t s2c{0};
    std::uint64_t quota{0};
};

PayloadTotals totals(Daemon& daemon) {
    const auto snapshot = daemon.services.stats.snapshot();
    const auto found = snapshot.users.find("alice");
    if (found == snapshot.users.end()) return {};
    return {found->second.payload_c2s_bytes, found->second.payload_s2c_bytes,
            found->second.quota_used_bytes};
}

std::uint64_t active_connections(Daemon& daemon) {
    return daemon.services.stats.snapshot().connections_active;
}

// ME route; the fake ME answers every request with kAnswerBytes.
FakeMe answering_me() {
    return FakeMe{me_secret(), 100000, 0ms, 1, 0ms, 0ms, true, 0, 30000};
}

void tweak_daemon(mtdd::Config& config) {
    config.handshake_timeout = 10s;
    config.idle_timeout = 60s;
}

bool add_alice(Daemon& daemon, std::optional<std::uint64_t> quota = std::nullopt) {
    mtdd::control::CreateUserRequest request;
    request.name = "alice";
    request.secret = std::string(kSecretHex);
    request.policy.data_quota_bytes = quota;
    return daemon.services.store->create_user(request).ok();
}

// Sends `count` 16 KiB requests and reads every answer.
bool exchange(TestClient& client, std::size_t first, std::size_t count) {
    for (std::size_t i = 0; i < count; ++i) {
        if (!client.send_message(burst_payload(first + i))) return false;
        Bytes answer;
        if (!client.read_message(answer, 5000) || answer.size() != kAnswerBytes) return false;
    }
    return true;
}

} // namespace

TEST(PayloadBatch, FlushesAtThresholdAndNeverCountsTwice) {
    mtdd::control::UserMetrics metrics;
    mtdd::detail::PayloadBatch batch;
    EXPECT_TRUE(batch.empty());
    EXPECT_FALSE(batch.add(Direction::client_to_server, 1000));
    EXPECT_FALSE(batch.add(Direction::server_to_client, 2000));
    EXPECT_FALSE(batch.empty());
    EXPECT_EQ(metrics.payload_c2s_bytes(), 0U) << "nothing is shared before a flush";

    batch.flush(&metrics);
    EXPECT_TRUE(batch.empty());
    EXPECT_EQ(metrics.payload_c2s_bytes(), 1000U);
    EXPECT_EQ(metrics.payload_s2c_bytes(), 2000U);
    EXPECT_EQ(metrics.quota_used_bytes(), 3000U);
    batch.flush(&metrics);  // e.g. the 1 Hz pass, then close
    EXPECT_EQ(metrics.payload_c2s_bytes(), 1000U);
    EXPECT_EQ(metrics.payload_s2c_bytes(), 2000U);

    // The threshold covers both directions together (quota counts both).
    EXPECT_FALSE(batch.add(Direction::client_to_server, mtdd::detail::kPayloadFlushBytes - 1));
    EXPECT_TRUE(batch.add(Direction::server_to_client, 1));
    batch.flush(&metrics);
    EXPECT_EQ(metrics.payload_c2s_bytes(), 1000U + mtdd::detail::kPayloadFlushBytes - 1);
    EXPECT_EQ(metrics.payload_s2c_bytes(), 2001U);
    EXPECT_EQ(metrics.quota_used_bytes(), 3000U + mtdd::detail::kPayloadFlushBytes);

    // A single frame larger than the threshold flushes at once.
    EXPECT_TRUE(batch.add(Direction::client_to_server, 4U * mtdd::detail::kPayloadFlushBytes));

    // Without metrics (never authenticated) the bytes are dropped, as before.
    batch.flush(nullptr);
    EXPECT_TRUE(batch.empty());
    EXPECT_EQ(metrics.payload_c2s_bytes(), 1000U + mtdd::detail::kPayloadFlushBytes - 1);
}

TEST(RuntimePayload, TotalsAreExactAfterClientClose) {
    auto me = answering_me();
    Daemon daemon(me.port(), true, tweak_daemon);
    ASSERT_TRUE(add_alice(daemon));
    ASSERT_TRUE(wait_for([&] { return daemon.services.metadata->snapshot() != nullptr; }, 3s));
    ASSERT_TRUE(wait_for([&] { return daemon.services.stats.ready(); }, 3s));

    TestClient client(daemon.port(), secret_bytes());
    ASSERT_TRUE(client.valid());
    ASSERT_TRUE(client.send_hello());
    ASSERT_TRUE(client.start_obfuscation(2));
    // 3 x 16 KiB stays below the 64 KiB flush threshold.
    ASSERT_TRUE(exchange(client, 0, 3));
    client.close();
    ASSERT_TRUE(wait_for([&] { return active_connections(daemon) == 0; }, 5s));

    const auto closed = totals(daemon);
    EXPECT_EQ(closed.c2s, 3U * kBurstSize);
    EXPECT_EQ(closed.s2c, 3U * kAnswerBytes);
    EXPECT_EQ(closed.quota, 3U * (kBurstSize + kAnswerBytes));
    // Later 1 Hz passes find nothing pending for the closed connection.
    std::this_thread::sleep_for(1200ms);
    const auto later = totals(daemon);
    EXPECT_EQ(later.c2s, closed.c2s);
    EXPECT_EQ(later.s2c, closed.s2c);
}

TEST(RuntimePayload, PeriodicPassPublishesLiveTotalsWithoutDoubleCountingOnClose) {
    auto me = answering_me();
    Daemon daemon(me.port(), true, tweak_daemon);
    ASSERT_TRUE(add_alice(daemon));
    ASSERT_TRUE(wait_for([&] { return daemon.services.metadata->snapshot() != nullptr; }, 3s));
    ASSERT_TRUE(wait_for([&] { return daemon.services.stats.ready(); }, 3s));

    TestClient client(daemon.port(), secret_bytes());
    ASSERT_TRUE(client.valid());
    ASSERT_TRUE(client.send_hello());
    ASSERT_TRUE(client.start_obfuscation(2));
    ASSERT_TRUE(exchange(client, 0, 1));
    // Below the threshold and still connected: only the 1 Hz pass publishes.
    ASSERT_TRUE(wait_for(
        [&] {
            const auto now = totals(daemon);
            return now.c2s == kBurstSize && now.s2c == kAnswerBytes;
        },
        3s));
    EXPECT_EQ(active_connections(daemon), 1U);

    // Flushed by the pass, then closed: the close flush adds nothing again.
    client.close();
    ASSERT_TRUE(wait_for([&] { return active_connections(daemon) == 0; }, 5s));
    const auto closed = totals(daemon);
    EXPECT_EQ(closed.c2s, kBurstSize);
    EXPECT_EQ(closed.s2c, kAnswerBytes);
}

TEST(RuntimePayload, ThresholdFlushPublishesWithoutWaitingForThePass) {
    auto me = answering_me();
    Daemon daemon(me.port(), true, tweak_daemon);
    ASSERT_TRUE(add_alice(daemon));
    ASSERT_TRUE(wait_for([&] { return daemon.services.metadata->snapshot() != nullptr; }, 3s));
    ASSERT_TRUE(wait_for([&] { return daemon.services.stats.ready(); }, 3s));

    TestClient client(daemon.port(), secret_bytes());
    ASSERT_TRUE(client.valid());
    ASSERT_TRUE(client.send_hello());
    ASSERT_TRUE(client.start_obfuscation(2));
    // Synchronise with a 1 Hz pass: once the first exchange is visible the
    // connection's batch is empty and the next pass is about a second away.
    ASSERT_TRUE(exchange(client, 0, 1));
    ASSERT_TRUE(wait_for(
        [&] {
            const auto now = totals(daemon);
            return now.c2s == kBurstSize && now.s2c == kAnswerBytes;
        },
        3s));
    // Four more requests reach 64 KiB pending (c2s + s2c) on the fourth, which
    // is flushed while it is decoded, i.e. before its answer is sent back.
    ASSERT_TRUE(exchange(client, 1, 4));
    EXPECT_EQ(totals(daemon).c2s, 5U * kBurstSize);
}

TEST(RuntimePayload, UserOverQuotaIsStillCutOffAndCountedExactly) {
    auto me = answering_me();
    Daemon daemon(me.port(), true, tweak_daemon);
    // The quota is reached exactly by the third answer, so the sweep cannot
    // close the session before that answer is on its way. The 48 KiB total
    // never reaches the 64 KiB flush threshold: only the 1 Hz pass publishes.
    constexpr std::uint64_t kQuota = 3U * (kBurstSize + kAnswerBytes);
    ASSERT_TRUE(add_alice(daemon, kQuota));
    ASSERT_TRUE(wait_for([&] { return daemon.services.metadata->snapshot() != nullptr; }, 3s));
    ASSERT_TRUE(wait_for([&] { return daemon.services.stats.ready(); }, 3s));

    TestClient client(daemon.port(), secret_bytes());
    ASSERT_TRUE(client.valid());
    ASSERT_TRUE(client.send_hello());
    ASSERT_TRUE(client.start_obfuscation(2));
    ASSERT_TRUE(exchange(client, 0, 3));
    // Enforcement trails by at most one flush plus one sweep (both 1 Hz).
    EXPECT_TRUE(client.wait_closed_for(4000));
    ASSERT_TRUE(wait_for([&] { return active_connections(daemon) == 0; }, 5s));
    const auto closed = totals(daemon);
    EXPECT_EQ(closed.c2s, 3U * kBurstSize);
    EXPECT_EQ(closed.s2c, 3U * kAnswerBytes);
    EXPECT_EQ(closed.quota, 3U * (kBurstSize + kAnswerBytes));

    TestClient late(daemon.port(), secret_bytes());
    ASSERT_TRUE(late.valid());
    EXPECT_FALSE(late.send_hello(0, 1));
    EXPECT_TRUE(wait_for(
        [&] { return stat_counter(daemon.services.stats, "rejected", "user_quota_exceeded") >= 1U; },
        2s));
}

TEST(RuntimePayload, ShutdownCountsLiveSessionsExactly) {
    auto me = answering_me();
    Daemon daemon(me.port(), true, tweak_daemon);
    ASSERT_TRUE(add_alice(daemon));
    ASSERT_TRUE(wait_for([&] { return daemon.services.metadata->snapshot() != nullptr; }, 3s));
    ASSERT_TRUE(wait_for([&] { return daemon.services.stats.ready(); }, 3s));

    TestClient client(daemon.port(), secret_bytes());
    ASSERT_TRUE(client.valid());
    ASSERT_TRUE(client.send_hello());
    ASSERT_TRUE(client.start_obfuscation(2));
    ASSERT_TRUE(exchange(client, 0, 2));
    // The reactor's finalize() closes the live session, which flushes it.
    daemon.stop();
    const auto stopped = totals(daemon);
    EXPECT_EQ(stopped.c2s, 2U * kBurstSize);
    EXPECT_EQ(stopped.s2c, 2U * kAnswerBytes);
}
