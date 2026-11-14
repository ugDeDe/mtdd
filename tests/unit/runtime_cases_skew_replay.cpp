#include "../support/runtime_fixture.hpp"

// ---------------------------------------------------------------------------
// A valid secret with a timestamp outside the window is a mis-clocked user,
// not a guesser: counted by skew, never scored as suspect, rejected as before.
// A replayed ClientHello gets what any unauthenticated visitor gets (masking)
// while every replay counter keeps its value.
// ---------------------------------------------------------------------------

namespace {

using mtdd::control::SuspectSignal;

struct SkewMaskingScope {
    explicit SkewMaskingScope(std::uint16_t port) {
        mtdd::detail::set_masking_endpoint_override(
            mtdd::detail::DirectEndpointOverride{"127.0.0.1", port});
    }
    ~SkewMaskingScope() { mtdd::detail::set_masking_endpoint_override(std::nullopt); }
    SkewMaskingScope(const SkewMaskingScope&) = delete;
    SkewMaskingScope& operator=(const SkewMaskingScope&) = delete;
};

struct SkewDirectScope {
    explicit SkewDirectScope(std::uint16_t port) {
        mtdd::detail::set_direct_endpoint_override(
            mtdd::detail::DirectEndpointOverride{"127.0.0.1", port});
    }
    ~SkewDirectScope() { mtdd::detail::set_direct_endpoint_override(std::nullopt); }
    SkewDirectScope(const SkewDirectScope&) = delete;
    SkewDirectScope& operator=(const SkewDirectScope&) = delete;
};

struct ReplayCapacityScope {
    explicit ReplayCapacityScope(std::size_t capacity) {
        mtdd::detail::set_replay_capacity_for_test(capacity);
    }
    ~ReplayCapacityScope() { mtdd::detail::set_replay_capacity_for_test(std::nullopt); }
    ReplayCapacityScope(const ReplayCapacityScope&) = delete;
    ReplayCapacityScope& operator=(const ReplayCapacityScope&) = delete;
};

void masking_on(mtdd::Config& config) {
    config.masking = true;
    config.suspects = true;
}

void direct_masking_on(mtdd::Config& config) {
    masking_on(config);
    config.direct_fallback_enabled = true;
    config.direct_fallback_dcs = {2};
}

Bytes hello_skewed(std::int64_t skew, std::uint8_t variant) {
    // skew = server clock - client timestamp: positive = client clock behind.
    return make_client_hello(secret_bytes(),
                             static_cast<std::uint32_t>(current_timestamp() - skew), kDomain,
                             variant);
}

std::uint64_t skew_count(Daemon& daemon, const std::string& side, const std::string& bucket) {
    return daemon.services.stats.snapshot().hello_clock_skew_total.at(side).at(bucket);
}

std::uint64_t skew_total(Daemon& daemon) {
    std::uint64_t total = 0;
    for (const auto& [side, buckets] : daemon.services.stats.snapshot().hello_clock_skew_total) {
        for (const auto& [bucket, value] : buckets) total += value;
    }
    return total;
}

std::uint32_t suspect_count(Daemon& daemon, SuspectSignal signal) {
    for (const auto& row : daemon.services.stats.suspects()) {
        if (row.ip == "127.0.0.1") return row.hits[static_cast<std::size_t>(signal)];
    }
    return 0;
}

std::uint64_t suspect_events(Daemon& daemon) {
    std::uint64_t total = 0;
    for (const auto value : daemon.services.stats.snapshot().suspect_events_total) total += value;
    return total;
}

std::uint64_t replay_rejections(Daemon& daemon) {
    std::uint64_t total = 0;
    for (const auto value : daemon.replay_per_worker()) total += value;
    return total;
}

std::uint64_t alice_active(Daemon& daemon) {
    const auto snapshot = daemon.services.stats.snapshot();
    const auto found = snapshot.users.find("alice");
    return found == snapshot.users.end() ? 0 : found->second.active_connections;
}

// Sends `wire` and expects the masking echo backend to return exactly it and
// nothing more: no ServerHello byte precedes or follows the echo.
void expect_masked_verbatim(Daemon& daemon, const Bytes& wire) {
    const int fd = connect_loopback(daemon.port());
    ASSERT_GE(fd, 0);
    ASSERT_TRUE(send_all(fd, wire));
    Bytes echoed(wire.size());
    EXPECT_TRUE(recv_exact(fd, echoed.data(), echoed.size(), 3000));
    EXPECT_EQ(echoed, wire);
    EXPECT_NE(peer_state(fd, 200), 1);
    ::close(fd);
}

void expect_closed_without_data(Daemon& daemon, const Bytes& wire) {
    const int fd = connect_loopback(daemon.port());
    ASSERT_GE(fd, 0);
    ASSERT_TRUE(send_all(fd, wire));
    EXPECT_NE(peer_state(fd, 1000), 1);
    EXPECT_TRUE(wait_closed(fd, 3000));
    ::close(fd);
}

} // namespace

TEST(ClockSkewHello, ValidSecretOutsideWindowIsMaskedCountedAndNeverSuspect) {
    EchoBackend echo;
    SkewMaskingScope scope(echo.port());
    Daemon daemon(1, false, masking_on);
    ASSERT_TRUE(daemon.services.add_user("alice", std::string(kSecretHex)));

    // A mis-clocked user retrying: three hellos 200 s behind, one 700 s ahead.
    for (std::uint8_t variant = 1; variant <= 3; ++variant) {
        expect_masked_verbatim(daemon, hello_skewed(200, variant));
    }
    expect_masked_verbatim(daemon, hello_skewed(-700, 4));
    EXPECT_GE(echo.accepted(), 4U);

    EXPECT_TRUE(wait_for([&] { return skew_total(daemon) >= 4U; }, 3000ms));
    EXPECT_EQ(skew_count(daemon, "behind", "le_300s"), 3U);
    EXPECT_EQ(skew_count(daemon, "ahead", "le_1200s"), 1U);
    EXPECT_EQ(skew_total(daemon), 4U);
    // Same wire accounting as any authentication failure that is masked.
    EXPECT_TRUE(wait_for(
        [&] { return stat_counter(daemon.services.stats, "handshakes", "failure") >= 4U; },
        3000ms));
    EXPECT_EQ(stat_counter(daemon.services.stats, "handshakes", "success"), 0U);
    EXPECT_EQ(stat_counter(daemon.services.stats, "handshakes", "replay"), 0U);
    // The address proved it knows a secret: no score at all.
    EXPECT_EQ(suspect_events(daemon), 0U);
    EXPECT_EQ(suspect_count(daemon, SuspectSignal::wrong_secret), 0U);
    EXPECT_EQ(suspect_count(daemon, SuspectSignal::junk), 0U);
    // No session, slot or IP was created for the user.
    EXPECT_EQ(alice_active(daemon), 0U);
    EXPECT_EQ(daemon.services.stats.snapshot().active_unique_ips, 0U);
}

TEST(ClockSkewHello, ValidSecretOutsideWindowIsClosedWithoutMasking) {
    Daemon daemon(1, false, [](mtdd::Config& config) {
        config.masking = false;
        config.suspects = true;
    });
    ASSERT_TRUE(daemon.services.add_user("alice", std::string(kSecretHex)));
    expect_closed_without_data(daemon, hello_skewed(2000, 1));
    EXPECT_TRUE(wait_for([&] { return skew_total(daemon) >= 1U; }, 3000ms));
    EXPECT_EQ(skew_count(daemon, "behind", "gt_1200s"), 1U);
    EXPECT_EQ(stat_counter(daemon.services.stats, "rejected", "auth_failed"), 1U);
    EXPECT_EQ(stat_counter(daemon.services.stats, "handshakes", "failure"), 1U);
    EXPECT_EQ(suspect_events(daemon), 0U);
    EXPECT_EQ(alice_active(daemon), 0U);
}

TEST(ClockSkewHello, WrongSecretWithWildTimestampIsStillAWrongSecret) {
    EchoBackend echo;
    SkewMaskingScope scope(echo.port());
    Daemon daemon(1, false, masking_on);
    ASSERT_TRUE(daemon.services.add_user("alice", std::string(kSecretHex)));
    A16 wrong{};
    wrong.fill(0xaa);
    expect_masked_verbatim(
        daemon, make_client_hello(wrong, current_timestamp() - 5000, kDomain, 1));
    EXPECT_TRUE(wait_for(
        [&] { return suspect_count(daemon, SuspectSignal::wrong_secret) >= 1U; }, 3000ms));
    EXPECT_EQ(skew_total(daemon), 0U);
}

TEST(ReplayHello, ReplayWithMaskingIsMaskedVerbatimAndCountedAsBefore) {
    mtdd::test::FakeDirectDc dc(2);
    SkewDirectScope direct(dc.port());
    EchoBackend echo;
    SkewMaskingScope scope(echo.port());
    Daemon daemon(1, true, direct_masking_on);
    ASSERT_TRUE(daemon.services.add_user("alice", std::string(kSecretHex)));
    ASSERT_TRUE(wait_for([&] { return daemon.services.metadata->snapshot() != nullptr; }, 3s));

    TestClient first(daemon.port(), secret_bytes());
    ASSERT_TRUE(first.valid());
    ASSERT_TRUE(first.send_hello(0, 7));
    ASSERT_TRUE(wait_for([&] { return alice_active(daemon) == 1U; }, 3000ms));

    expect_masked_verbatim(daemon, first.hello_bytes());
    EXPECT_GE(echo.accepted(), 1U);
    EXPECT_TRUE(wait_for(
        [&] { return stat_counter(daemon.services.stats, "handshakes", "replay") >= 1U; },
        3000ms));
    EXPECT_EQ(stat_counter(daemon.services.stats, "handshakes", "replay"), 1U);
    // start_fallback() must not turn the replay into a second "failure".
    EXPECT_EQ(stat_counter(daemon.services.stats, "handshakes", "failure"), 0U);
    EXPECT_EQ(stat_counter(daemon.services.stats, "rejected", "auth_failed"), 1U);
    EXPECT_EQ(replay_rejections(daemon), 1U);
    EXPECT_EQ(suspect_count(daemon, SuspectSignal::junk), 1U);
    EXPECT_EQ(skew_total(daemon), 0U);
    // The replay entry stays: the same hello is masked again.
    expect_masked_verbatim(daemon, first.hello_bytes());
    EXPECT_TRUE(wait_for([&] { return replay_rejections(daemon) == 2U; }, 3000ms));

    // The legitimate session is untouched and still relays.
    EXPECT_EQ(alice_active(daemon), 1U);
    ASSERT_TRUE(first.start_obfuscation(2));
    const Bytes payload(64, 0x3c);
    ASSERT_TRUE(first.send_message(payload));
    Bytes got;
    ASSERT_TRUE(first.read_message(got));
    EXPECT_EQ(got, payload);
}

TEST(ReplayHello, ReplayWithoutMaskingIsClosedAsBefore) {
    Daemon daemon(1, false, [](mtdd::Config& config) {
        config.masking = false;
        config.suspects = true;
    });
    ASSERT_TRUE(daemon.services.add_user("alice", std::string(kSecretHex)));
    TestClient first(daemon.port(), secret_bytes());
    ASSERT_TRUE(first.valid());
    ASSERT_TRUE(first.send_hello(0, 8));
    expect_closed_without_data(daemon, first.hello_bytes());
    EXPECT_TRUE(wait_for(
        [&] { return stat_counter(daemon.services.stats, "handshakes", "replay") >= 1U; },
        3000ms));
    EXPECT_EQ(stat_counter(daemon.services.stats, "rejected", "auth_failed"), 1U);
    EXPECT_EQ(replay_rejections(daemon), 1U);
    EXPECT_EQ(suspect_count(daemon, SuspectSignal::junk), 1U);
    EXPECT_FALSE(first.wait_closed_for(100));
}

TEST(ReplayHello, SaturatedReplayCacheWithMaskingIsMasked) {
    ReplayCapacityScope capacity(1);
    EchoBackend echo;
    SkewMaskingScope scope(echo.port());
    Daemon daemon(1, false, masking_on);
    ASSERT_TRUE(daemon.services.add_user("alice", std::string(kSecretHex)));
    TestClient first(daemon.port(), secret_bytes());
    ASSERT_TRUE(first.valid());
    ASSERT_TRUE(first.send_hello(0, 9));

    // A distinct, valid hello: the cache is full, so it is refused as replay.
    expect_masked_verbatim(daemon, hello_skewed(0, 10));
    EXPECT_GE(echo.accepted(), 1U);
    EXPECT_TRUE(wait_for(
        [&] { return stat_counter(daemon.services.stats, "handshakes", "replay") >= 1U; },
        3000ms));
    EXPECT_EQ(stat_counter(daemon.services.stats, "handshakes", "failure"), 0U);
    EXPECT_EQ(stat_counter(daemon.services.stats, "rejected", "overload"), 1U);
    EXPECT_EQ(stat_counter(daemon.services.stats, "rejected", "auth_failed"), 0U);
    EXPECT_EQ(replay_rejections(daemon), 1U);
    EXPECT_EQ(suspect_count(daemon, SuspectSignal::junk), 0U);
    EXPECT_FALSE(first.wait_closed_for(100));
}

TEST(ReplayHello, SaturatedReplayCacheWithoutMaskingIsClosedAsBefore) {
    ReplayCapacityScope capacity(1);
    Daemon daemon(1, false);
    ASSERT_TRUE(daemon.services.add_user("alice", std::string(kSecretHex)));
    TestClient first(daemon.port(), secret_bytes());
    ASSERT_TRUE(first.valid());
    ASSERT_TRUE(first.send_hello(0, 11));
    expect_closed_without_data(daemon, hello_skewed(0, 12));
    EXPECT_TRUE(wait_for(
        [&] { return stat_counter(daemon.services.stats, "rejected", "overload") >= 1U; },
        3000ms));
    EXPECT_EQ(stat_counter(daemon.services.stats, "handshakes", "replay"), 1U);
    EXPECT_EQ(replay_rejections(daemon), 1U);
}

TEST(ClockSkewHello, SameSkewedHelloTwiceIsAReplay) {
    EchoBackend echo;
    SkewMaskingScope scope(echo.port());
    Daemon daemon(1, false, masking_on);
    ASSERT_TRUE(daemon.services.add_user("alice", std::string(kSecretHex)));
    // Older than the window and the replay retention: only the repeated
    // client random tells a stale replay from a mis-clocked user.
    const Bytes hello = hello_skewed(400, 1);
    expect_masked_verbatim(daemon, hello);
    EXPECT_TRUE(wait_for([&] { return skew_total(daemon) >= 1U; }, 3000ms));
    EXPECT_EQ(suspect_events(daemon), 0U);

    expect_masked_verbatim(daemon, hello);
    EXPECT_TRUE(wait_for(
        [&] { return stat_counter(daemon.services.stats, "handshakes", "replay") >= 1U; },
        3000ms));
    EXPECT_EQ(skew_count(daemon, "behind", "le_600s"), 1U);
    EXPECT_EQ(skew_total(daemon), 1U);
    EXPECT_EQ(suspect_count(daemon, SuspectSignal::junk), 1U);
    EXPECT_EQ(suspect_count(daemon, SuspectSignal::wrong_secret), 0U);
    EXPECT_EQ(stat_counter(daemon.services.stats, "handshakes", "replay"), 1U);
    EXPECT_EQ(stat_counter(daemon.services.stats, "handshakes", "failure"), 1U);
    EXPECT_EQ(stat_counter(daemon.services.stats, "rejected", "auth_failed"), 1U);
    EXPECT_EQ(replay_rejections(daemon), 1U);
    EXPECT_GE(echo.accepted(), 2U);
}

TEST(ClockSkewHello, DistinctSkewedHellosFromOneUserAreAllCounted) {
    EchoBackend echo;
    SkewMaskingScope scope(echo.port());
    Daemon daemon(1, false, masking_on);
    ASSERT_TRUE(daemon.services.add_user("alice", std::string(kSecretHex)));
    expect_masked_verbatim(daemon, hello_skewed(400, 1));
    expect_masked_verbatim(daemon, hello_skewed(400, 2));
    EXPECT_TRUE(wait_for([&] { return skew_total(daemon) >= 2U; }, 3000ms));
    EXPECT_EQ(skew_count(daemon, "behind", "le_600s"), 2U);
    EXPECT_EQ(suspect_events(daemon), 0U);
    EXPECT_EQ(stat_counter(daemon.services.stats, "handshakes", "replay"), 0U);
}
