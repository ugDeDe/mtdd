#include "../support/runtime_fixture.hpp"

// ---------------------------------------------------------------------------
// JA4 recording: the process-wide table (GET /v1/ja4) counts each recorded
// ClientHello by outcome, and suspect entries carry the JA4 of the hello that
// made them. Admission itself is unchanged (see runtime_cases_hello_admission).
// ---------------------------------------------------------------------------

namespace {

using mtdd::control::Ja4Outcome;

std::uint64_t ja4_count(Daemon& daemon, const std::string& ja4, Ja4Outcome outcome) {
    for (const auto& entry : daemon.services.stats.ja4().snapshot().entries) {
        if (entry.ja4 == ja4) return entry.counts[static_cast<std::size_t>(outcome)];
    }
    return 0;
}

// Sends `hello`; true when a ServerHello came back, false when closed.
bool send_hello(Daemon& daemon, const Bytes& hello) {
    const int fd = connect_loopback(daemon.port());
    if (fd < 0) return false;
    bool server_hello = false;
    if (send_all(fd, hello)) {
        std::uint8_t head[6]{};
        if (recv_exact(fd, head, sizeof(head), 3000)) {
            server_hello = head[0] == 0x16 && head[5] == 0x02;
        } else {
            (void)wait_closed(fd, 3000);
        }
    }
    ::close(fd);
    return server_hello;
}

std::string expected_ja4(const Bytes& hello) {
    const auto value = mtdd::protocol::client_hello_ja4(hello);
    return value.value_or("");
}

} // namespace

TEST(Ja4Recording, AuthenticatedAndReplayedHellosAreCounted) {
    Daemon daemon(1, false, [](mtdd::Config& config) { config.masking = false; });
    ASSERT_TRUE(daemon.services.add_user("alice", std::string(kSecretHex)));
    const Bytes hello = make_client_hello(secret_bytes(), current_timestamp(), kDomain, 11);
    const std::string ja4 = expected_ja4(hello);
    ASSERT_EQ(ja4.size(), 36u);
    EXPECT_EQ(ja4.substr(0, 10), "t12d020300");  // see Ja4.FakeTlsHelloOfTheFixture...

    ASSERT_TRUE(send_hello(daemon, hello));
    EXPECT_TRUE(wait_for([&] { return ja4_count(daemon, ja4, Ja4Outcome::authenticated) == 1; },
                         3000ms));
    // The same signed hello again: a replay, refused, counted as replay.
    EXPECT_FALSE(send_hello(daemon, hello));
    EXPECT_TRUE(wait_for([&] { return ja4_count(daemon, ja4, Ja4Outcome::replay) == 1; }, 3000ms));
    EXPECT_EQ(ja4_count(daemon, ja4, Ja4Outcome::unauthenticated), 0u);
    EXPECT_EQ(daemon.services.stats.ja4().unsampled(), 0u);
}

TEST(Ja4Recording, FailedHelloIsCountedAndStoredOnTheSuspect) {
    Daemon daemon(1, false, [](mtdd::Config& config) {
        config.masking = false;
        config.suspects = true;
    });
    ASSERT_TRUE(daemon.services.add_user("alice", std::string(kSecretHex)));
    A16 wrong{};
    wrong.fill(0xaa);
    const Bytes hello = make_client_hello(wrong, current_timestamp(), kDomain, 12);
    const std::string ja4 = expected_ja4(hello);
    EXPECT_FALSE(send_hello(daemon, hello));
    EXPECT_TRUE(wait_for([&] { return ja4_count(daemon, ja4, Ja4Outcome::unauthenticated) == 1; },
                         3000ms));
    EXPECT_EQ(ja4_count(daemon, ja4, Ja4Outcome::authenticated), 0u);
    bool stored = false;
    EXPECT_TRUE(wait_for([&] {
        for (const auto& row : daemon.services.stats.suspects()) {
            if (row.ip == "127.0.0.1" && row.ja4 == ja4) stored = true;
        }
        return stored;
    }, 3000ms));

    // A foreign SNI costs no HMAC; it is still fingerprinted within budget.
    // JA4 ignores the SNI value, so this is the same fingerprint again.
    const Bytes foreign = make_client_hello(wrong, current_timestamp(), "other.org", 13);
    ASSERT_EQ(expected_ja4(foreign), ja4);
    EXPECT_FALSE(send_hello(daemon, foreign));
    EXPECT_TRUE(wait_for([&] {
        return ja4_count(daemon, ja4, Ja4Outcome::unauthenticated) == 2;
    }, 3000ms));
}

TEST(Ja4Recording, MalformedHelloIsNotFingerprintedAndDoesNotCrash) {
    Daemon daemon(1, false, [](mtdd::Config& config) {
        config.masking = false;
        config.suspects = true;
        config.watch_ips = {"127.0.0.1"};  // watch_hello computes the JA4 too
    });
    ASSERT_TRUE(daemon.services.add_user("alice", std::string(kSecretHex)));
    Bytes hello = make_client_hello(secret_bytes(), current_timestamp(), kDomain, 14);
    hello[5] = 0x02;  // not a ClientHello handshake message
    EXPECT_FALSE(send_hello(daemon, hello));
    Bytes garbage(200, 0xff);
    garbage[0] = 0x16;
    garbage[1] = 0x03;
    garbage[2] = 0x01;
    garbage[3] = 0x00;
    garbage[4] = 195;
    EXPECT_FALSE(send_hello(daemon, garbage));
    // The proxy still serves a valid hello afterwards.
    EXPECT_TRUE(send_hello(daemon, make_client_hello(secret_bytes(), current_timestamp(), kDomain, 15)));
    EXPECT_TRUE(wait_for([&] { return daemon.services.stats.ja4().size() == 1; }, 3000ms));
}
