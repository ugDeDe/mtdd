#include "../support/runtime_fixture.hpp"

#include <sys/ioctl.h>

// ---------------------------------------------------------------------------
// server_hello_delay_min_ms / server_hello_delay_max_ms: the FakeTLS answer is
// held for a per-client random delay (a real server answers only after its
// own key exchange), the client is not read meanwhile, and a client that
// leaves during the delay leaves nothing behind.
// ---------------------------------------------------------------------------

namespace {

using Clock = std::chrono::steady_clock;

void delay_ms(mtdd::Config& config, int min, int max) {
    config.server_hello_delay_min = std::chrono::milliseconds(min);
    config.server_hello_delay_max = std::chrono::milliseconds(max);
}

std::uint32_t now_unix() {
    return static_cast<std::uint32_t>(std::chrono::duration_cast<std::chrono::seconds>(
                                          std::chrono::system_clock::now().time_since_epoch())
                                          .count());
}

// Reads ServerHello, CCS and the ApplicationData flight; the time from
// `sent` to the first byte, or nullopt when the answer is not that shape.
std::optional<Clock::duration> read_server_flight(int fd, Clock::time_point sent,
                                                  int timeout_ms = 3000) {
    std::optional<Clock::duration> first;
    for (const std::uint8_t type : {std::uint8_t{0x16}, std::uint8_t{0x14}, std::uint8_t{0x17}}) {
        std::array<std::uint8_t, 5> header{};
        if (!recv_exact(fd, header.data(), header.size(), timeout_ms)) return std::nullopt;
        if (!first) first = Clock::now() - sent;
        if (header[0] != type) return std::nullopt;
        Bytes body((static_cast<std::size_t>(header[3]) << 8) | header[4]);
        if (!body.empty() && !recv_exact(fd, body.data(), body.size(), timeout_ms)) {
            return std::nullopt;
        }
    }
    return first;
}

// One authenticated hello; the delay until its ServerHello arrives.
std::optional<Clock::duration> hello_delay(std::uint16_t port, std::uint8_t variant) {
    const int fd = connect_loopback(port);
    if (fd < 0) return std::nullopt;
    const auto hello = make_client_hello(secret_bytes(), now_unix(), kDomain, variant);
    const auto sent = Clock::now();
    std::optional<Clock::duration> out;
    if (send_all(fd, hello)) out = read_server_flight(fd, sent);
    ::close(fd);
    return out;
}

// Closes with RST: SO_LINGER 0.
void reset_close(int fd) {
    linger option{1, 0};
    ::setsockopt(fd, SOL_SOCKET, SO_LINGER, &option, sizeof(option));
    ::close(fd);
}

}  // namespace

TEST(ServerHelloDelay, HelloIsHeldForTheDelayAndThePipelinedSessionStillWorks) {
    FakeMe me{me_secret()};
    testing::internal::CaptureStderr();
    {
        Daemon daemon(me.port(), true, [](mtdd::Config& config) {
            delay_ms(config, 250, 250);
            config.watch_ips = {"127.0.0.1"};
        });
        ASSERT_TRUE(daemon.services.add_user("alice", std::string(kSecretHex)));
        ASSERT_TRUE(wait_for([&] { return daemon.services.stats.ready(); }, 3s));

        TestClient client(daemon.port(), secret_bytes());
        ASSERT_TRUE(client.valid());
        // The client does not wait for the ServerHello: CCS, obfuscation and
        // the first message follow the hello at once. None of it may be read
        // (nor answered) before the held hello is out.
        const auto sent = Clock::now();
        ASSERT_TRUE(client.send_hello_bytes(
            make_client_hello(secret_bytes(), now_unix(), kDomain)));
        ASSERT_TRUE(client.start_obfuscation(2));
        ASSERT_TRUE(client.send_message(burst_payload(0)));
        const auto first = read_server_flight(client.fd(), sent);
        ASSERT_TRUE(first.has_value()) << "the ServerHello flight comes first, whole";
        EXPECT_GE(*first, 250ms);
        EXPECT_LT(*first, 2s);

        Bytes response;
        ASSERT_TRUE(client.read_message(response));
        EXPECT_EQ(response, (Bytes{0xaa, 0xbb, 0xcc, 0xdd, 0x11, 0x22, 0x33, 0x44}));
        EXPECT_GE(stat_counter(daemon.services.stats, "handshakes", "success"), 1U);
    }
    const std::string log = testing::internal::GetCapturedStderr();
    EXPECT_NE(log.find(" server_hello delay_ms=250"), std::string::npos) << log;
}

TEST(ServerHelloDelay, DelaysAreDrawnFromTheConfiguredRange) {
    Daemon daemon(1, false, [](mtdd::Config& config) { delay_ms(config, 120, 220); });
    ASSERT_TRUE(daemon.services.add_user("alice", std::string(kSecretHex)));
    for (std::uint8_t variant = 0; variant < 6; ++variant) {
        const auto delay = hello_delay(daemon.port(), variant);
        ASSERT_TRUE(delay.has_value());
        EXPECT_GE(*delay, 120ms);
        EXPECT_LT(*delay, 220ms + 500ms) << "bounded by the maximum plus scheduling";
    }
}

TEST(ServerHelloDelay, ZeroDelayAnswersAtOnce) {
    Daemon daemon(1, false, [](mtdd::Config& config) { delay_ms(config, 0, 0); });
    ASSERT_TRUE(daemon.services.add_user("alice", std::string(kSecretHex)));
    std::vector<Clock::duration> delays;
    for (std::uint8_t variant = 0; variant < 5; ++variant) {
        const auto delay = hello_delay(daemon.port(), variant);
        ASSERT_TRUE(delay.has_value());
        delays.push_back(*delay);
    }
    // No timer at all: well below the smallest delay a deadline could add on
    // a loaded (sanitizer) host, judged by the fastest of a few hellos.
    EXPECT_LT(*std::min_element(delays.begin(), delays.end()), 100ms);
}

TEST(ServerHelloDelay, ClientResetDuringTheDelayIsClosedAndCounted) {
    Daemon daemon(1, false, [](mtdd::Config& config) { delay_ms(config, 800, 800); });
    ASSERT_TRUE(daemon.services.add_user("alice", std::string(kSecretHex)));
    const auto failures = stat_counter(daemon.services.stats, "handshakes", "failure");

    const int fd = connect_loopback(daemon.port());
    ASSERT_GE(fd, 0);
    ASSERT_TRUE(send_all(fd, make_client_hello(secret_bytes(), now_unix(), kDomain)));
    // Authenticated and held: one active connection, nothing answered yet.
    ASSERT_TRUE(wait_for([&] {
        const auto snapshot = daemon.services.stats.snapshot();
        const auto user = snapshot.users.find("alice");
        return user != snapshot.users.end() && user->second.active_connections == 1U;
    }, 2s));
    int pending = 0;
    ASSERT_EQ(::ioctl(fd, FIONREAD, &pending), 0);
    EXPECT_EQ(pending, 0) << "the hello is still held";
    const auto reset_at = Clock::now();
    reset_close(fd);

    // Closed on the reset itself, long before the held hello was due.
    ASSERT_TRUE(wait_for([&] {
        return daemon.services.stats.snapshot().connections_active == 0;
    }, 2s));
    EXPECT_LT(Clock::now() - reset_at, 700ms);
    EXPECT_TRUE(wait_for([&] {
        return stat_counter(daemon.services.stats, "handshakes", "failure") == failures + 1;
    }, 1s));
    EXPECT_EQ(daemon.services.stats.snapshot().users.at("alice").active_connections, 0U);

    // The dropped deadline must not fire for anything: past its due time the
    // reactor still serves a fresh client normally.
    std::this_thread::sleep_for(300ms);
    const auto delay = hello_delay(daemon.port(), 7);
    ASSERT_TRUE(delay.has_value());
    EXPECT_GE(*delay, 800ms);
}

TEST(ServerHelloDelay, ShutdownDuringTheDelayClosesTheHeldClient) {
    Daemon daemon(1, false, [](mtdd::Config& config) { delay_ms(config, 1000, 1000); });
    ASSERT_TRUE(daemon.services.add_user("alice", std::string(kSecretHex)));
    const int fd = connect_loopback(daemon.port());
    ASSERT_GE(fd, 0);
    ASSERT_TRUE(send_all(fd, make_client_hello(secret_bytes(), now_unix(), kDomain)));
    ASSERT_TRUE(wait_for([&] {
        const auto snapshot = daemon.services.stats.snapshot();
        const auto user = snapshot.users.find("alice");
        return user != snapshot.users.end() && user->second.active_connections == 1U;
    }, 2s)) << "authenticated and held";
    const auto start = Clock::now();
    daemon.stop();
    EXPECT_LT(Clock::now() - start, 900ms) << "shutdown waited for the held hello";
    EXPECT_TRUE(wait_closed(fd, 1000));
    ::close(fd);
}

// ---------------------------------------------------------------------------
// server_hello_delay_auto: the processing time measured on the real server
// (ClientHello -> ServerHello latency minus the TCP connect round trip) over
// the last few probe handshakes, and the per-client delay drawn from it.
// Pure functions: injected timings, no network.
// ---------------------------------------------------------------------------

namespace {

using std::chrono::microseconds;
using mtdd::detail::ServerTiming;
using mtdd::detail::ServerTimingHistory;

ServerTiming timing_us(std::int64_t low, std::int64_t median, std::int64_t high) {
    return ServerTiming{microseconds(low), microseconds(median), microseconds(high), 8};
}

}  // namespace

TEST(ServerHelloAutoDelay, ProcessingIsTheHelloLatencyMinusOneConnectRoundTrip) {
    using mtdd::detail::server_processing_time;
    EXPECT_EQ(server_processing_time(microseconds(20000), microseconds(32000)), microseconds(12000));
    EXPECT_EQ(server_processing_time(microseconds(0), microseconds(4500)), microseconds(4500))
        << "an immediate connect measures no round trip";
    EXPECT_EQ(server_processing_time(microseconds(20000), microseconds(20000)), microseconds(0));
    EXPECT_EQ(server_processing_time(microseconds(25000), microseconds(19000)), microseconds(0))
        << "a noisy RTT above the latency clamps at 0, never negative";
}

TEST(ServerHelloAutoDelay, HistoryKeepsTheLastEightSamplesAndItsQuartiles) {
    ServerTimingHistory history;
    EXPECT_FALSE(history.summary().has_value()) << "unmeasured";

    history.add(microseconds(7000));
    const auto one = history.summary();
    ASSERT_TRUE(one.has_value());
    EXPECT_EQ(one->low, microseconds(7000));
    EXPECT_EQ(one->median, microseconds(7000));
    EXPECT_EQ(one->high, microseconds(7000));
    EXPECT_EQ(one->samples, 1U);

    // Out of order on purpose: the summary sorts. {1,2,3,4,7}: 2, 3, 4.
    for (const int ms : {4, 1, 3, 2}) history.add(microseconds(ms * 1000));
    const auto five = history.summary();
    ASSERT_TRUE(five.has_value());
    EXPECT_EQ(five->low, microseconds(2000));
    EXPECT_EQ(five->median, microseconds(3000));
    EXPECT_EQ(five->high, microseconds(4000));
    EXPECT_EQ(five->samples, 5U);

    // Interpolated between neighbours for an even count.
    ServerTimingHistory even;
    for (int ms = 1; ms <= 8; ++ms) even.add(microseconds(ms * 1000));
    const auto eight = even.summary();
    ASSERT_TRUE(eight.has_value());
    EXPECT_EQ(eight->low, microseconds(2750));  // 1 + 7 * 0.25
    EXPECT_EQ(eight->median, microseconds(4500));
    EXPECT_EQ(eight->high, microseconds(6250));
    EXPECT_EQ(eight->samples, ServerTimingHistory::kCapacity);

    // Bounded: eight newer samples push every old one out.
    for (int i = 0; i < 8; ++i) even.add(microseconds(90000));
    EXPECT_EQ(even.size(), ServerTimingHistory::kCapacity);
    const auto replaced = even.summary();
    ASSERT_TRUE(replaced.has_value());
    EXPECT_EQ(replaced->low, microseconds(90000));
    EXPECT_EQ(replaced->high, microseconds(90000));

    // One more replaces only the oldest: {0, 90 x 7}.
    even.add(microseconds(0));
    const auto mixed = even.summary();
    ASSERT_TRUE(mixed.has_value());
    EXPECT_EQ(mixed->low, microseconds(90000));
    EXPECT_EQ(mixed->high, microseconds(90000));
    EXPECT_EQ(mixed->samples, ServerTimingHistory::kCapacity);

    ServerTimingHistory negative;
    negative.add(microseconds(-5));
    EXPECT_EQ(negative.summary()->low, microseconds(0)) << "a negative sample is stored as 0";
}

TEST(ServerHelloAutoDelay, PicksWithinTheMeasuredSpreadOnlyWhenEnabledAndUnset) {
    using mtdd::detail::pick_server_hello_delay;
    mtdd::Config config;
    ASSERT_TRUE(config.server_hello_delay_auto) << "on by default";
    const std::optional<ServerTiming> measured = timing_us(3000, 4000, 6000);

    // Within [p25, p75] for any draw, both ends included.
    for (const std::uint32_t draw : {0U, 1U, 2999U, 3000U, 12345U, 0xffffffffU}) {
        const auto choice = pick_server_hello_delay(config, measured, draw);
        EXPECT_TRUE(choice.automatic);
        EXPECT_GE(choice.delay, microseconds(3000)) << draw;
        EXPECT_LE(choice.delay, microseconds(6000)) << draw;
    }
    EXPECT_EQ(pick_server_hello_delay(config, measured, 0).delay, microseconds(3000));
    EXPECT_EQ(pick_server_hello_delay(config, measured, 3000).delay, microseconds(6000));

    // Unmeasured: no delay, as before the feature.
    const auto unmeasured = pick_server_hello_delay(config, std::nullopt, 12345);
    EXPECT_FALSE(unmeasured.automatic);
    EXPECT_EQ(unmeasured.delay, microseconds(0));

    // Disabled: the measurement is ignored.
    config.server_hello_delay_auto = false;
    const auto disabled = pick_server_hello_delay(config, measured, 12345);
    EXPECT_FALSE(disabled.automatic);
    EXPECT_EQ(disabled.delay, microseconds(0));
}

TEST(ServerHelloAutoDelay, ManualBoundsOverrideTheMeasurement) {
    using mtdd::detail::pick_server_hello_delay;
    mtdd::Config config;
    const std::optional<ServerTiming> measured = timing_us(40000, 50000, 60000);
    delay_ms(config, 7, 7);
    const auto fixed = pick_server_hello_delay(config, measured, 0xffffffffU);
    EXPECT_FALSE(fixed.automatic);
    EXPECT_EQ(fixed.delay, microseconds(7000));

    delay_ms(config, 10, 20);
    for (const std::uint32_t draw : {0U, 5U, 10U, 11U, 0xffffffffU}) {
        const auto choice = pick_server_hello_delay(config, measured, draw);
        EXPECT_FALSE(choice.automatic);
        EXPECT_GE(choice.delay, microseconds(10000));
        EXPECT_LE(choice.delay, microseconds(20000));
        EXPECT_EQ(choice.delay.count() % 1000, 0) << "whole milliseconds, as before";
    }
    // A minimum alone is still manual.
    mtdd::Config min_only;
    min_only.server_hello_delay_min = std::chrono::milliseconds(5);
    EXPECT_EQ(pick_server_hello_delay(min_only, measured, 99).delay, microseconds(5000));
}

TEST(ServerHelloAutoDelay, AutomaticDelayIsCappedAtOneHundredMilliseconds) {
    using mtdd::detail::pick_server_hello_delay;
    const mtdd::Config config;
    const microseconds cap = mtdd::Config::kMaxAutoServerHelloDelay;
    ASSERT_EQ(cap, microseconds(100000));
    // Entirely above the cap: exactly the cap.
    for (const std::uint32_t draw : {0U, 7U, 0xffffffffU}) {
        const auto choice =
            pick_server_hello_delay(config, timing_us(400000, 500000, 900000), draw);
        EXPECT_TRUE(choice.automatic);
        EXPECT_EQ(choice.delay, cap);
    }
    // Straddling it: the upper end is cut, the lower one kept.
    for (std::uint32_t draw = 0; draw < 50000; draw += 997) {
        const auto choice =
            pick_server_hello_delay(config, timing_us(80000, 120000, 300000), draw);
        EXPECT_GE(choice.delay, microseconds(80000));
        EXPECT_LE(choice.delay, cap);
    }
    // A measured 0 (processing within the RTT noise) is an automatic 0.
    const auto zero = pick_server_hello_delay(config, timing_us(0, 0, 0), 12345);
    EXPECT_TRUE(zero.automatic);
    EXPECT_EQ(zero.delay, microseconds(0));
}

TEST(ServerHelloAutoDelay, AppliedDelaysAreCountedByBucket) {
    mtdd::control::Statistics stats;
    for (const int us : {0, 1000, 1001, 5000, 9999, 25000, 50001, 100000}) {
        stats.server_hello_auto_delay(microseconds(us));
    }
    stats.server_hello_auto_delay(microseconds(-3));  // clamped to 0
    const auto snapshot = stats.snapshot();
    const auto& buckets = snapshot.server_hello_auto_delay_total;
    ASSERT_EQ(buckets.size(), mtdd::control::kAutoDelayBuckets) << "every label present";
    EXPECT_EQ(buckets.at("le_1ms"), 3U);
    EXPECT_EQ(buckets.at("le_5ms"), 2U);
    EXPECT_EQ(buckets.at("le_10ms"), 1U);
    EXPECT_EQ(buckets.at("le_25ms"), 1U);
    EXPECT_EQ(buckets.at("le_50ms"), 0U);
    EXPECT_EQ(buckets.at("le_100ms"), 2U);
    EXPECT_EQ(snapshot.server_hello_auto_delay_us_total, 192001U);
    const auto text = stats.prometheus_text();
    EXPECT_NE(text.find("mtdd_server_hello_auto_delay_total{delay=\"le_100ms\"} 2"),
              std::string::npos);
    EXPECT_NE(text.find("mtdd_server_hello_auto_delay_us_total 192001"), std::string::npos);
    EXPECT_EQ(text.find("mtdd_masking_server_processing_us"), std::string::npos)
        << "no domain measured, no per-domain gauge";

    stats.set_server_timing_lister([] {
        return std::vector<mtdd::control::Statistics::ServerTimingInfo>{
            {"front.example", 1500, 2000, 2750, 8}};
    });
    const auto with_domain = stats.prometheus_text();
    EXPECT_NE(with_domain.find("mtdd_masking_server_processing_us{domain=\"front.example\","
                               "quantile=\"0.5\"} 2000"),
              std::string::npos);
    EXPECT_NE(with_domain.find("mtdd_masking_server_processing_us{domain=\"front.example\","
                               "quantile=\"0.75\"} 2750"),
              std::string::npos);
    EXPECT_NE(with_domain.find("mtdd_masking_server_processing_samples{domain=\"front.example\"} 8"),
              std::string::npos);
    stats.set_server_timing_lister({});
}
