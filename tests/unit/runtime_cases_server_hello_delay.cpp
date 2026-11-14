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
