#include "../support/runtime_fixture.hpp"

// ---------------------------------------------------------------------------
// ClientHello admission cost: only keys whose user may authenticate on the
// hello's SNI are tried (a foreign SNI costs no HMAC), the user that last
// authenticated from an address or prefix is tried first, and an address
// with many failed authentications is limited to its hinted keys. Every miss
// takes the unchanged unauthenticated path. Counted by
// mtdd_handshake_hmac_attempts_total / mtdd_handshake_throttled_total.
// ---------------------------------------------------------------------------

namespace {

constexpr std::string_view kFrontDomain = "front.example";

struct AdmissionMaskingScope {
    explicit AdmissionMaskingScope(std::uint16_t port) {
        mtdd::detail::set_masking_endpoint_override(
            mtdd::detail::DirectEndpointOverride{"127.0.0.1", port});
    }
    ~AdmissionMaskingScope() { mtdd::detail::set_masking_endpoint_override(std::nullopt); }
    AdmissionMaskingScope(const AdmissionMaskingScope&) = delete;
    AdmissionMaskingScope& operator=(const AdmissionMaskingScope&) = delete;
};

A16 user_secret(std::uint8_t user) {
    A16 out{};
    for (std::size_t i = 0; i < out.size(); ++i) {
        out[i] = static_cast<std::uint8_t>(0xa0 + user * 3 + i);
    }
    return out;
}

std::string user_secret_hex(std::uint8_t user) {
    static constexpr char kHex[] = "0123456789abcdef";
    std::string out;
    for (const auto byte : user_secret(user)) {
        out.push_back(kHex[byte >> 4]);
        out.push_back(kHex[byte & 15]);
    }
    return out;
}

std::uint64_t hmac_attempts(Daemon& daemon) {
    return daemon.services.stats.snapshot().hello_hmac_attempts_total;
}

std::uint64_t throttled(Daemon& daemon) {
    return daemon.services.stats.snapshot().hello_throttled_total;
}

// Each hello is unique (variant), so the replay cache never interferes.
std::uint8_t next_variant() {
    static std::uint8_t variant = 0;
    return ++variant;
}

enum class Answer { server_hello, echoed, closed, other };

// One hello from `source`; classifies the first answer. The counters are
// updated on the reactor before it answers or closes.
Answer hello_from(Daemon& daemon, const char* source, const A16& secret,
                  std::string_view sni = kDomain) {
    const int fd = connect_loopback_from(daemon.port(), source);
    if (fd < 0) return Answer::other;
    const Bytes hello = make_client_hello(secret, current_timestamp(), sni, next_variant());
    Answer answer = Answer::other;
    if (send_all(fd, hello)) {
        std::uint8_t head[6]{};
        if (!recv_exact(fd, head, sizeof(head), 3000)) {
            answer = wait_closed(fd, 3000) ? Answer::closed : Answer::other;
        } else if (head[0] == 0x16 && head[5] == 0x02) {
            answer = Answer::server_hello;
        } else if (std::equal(std::begin(head), std::end(head), hello.begin())) {
            // The masking echo returns the hello verbatim; read it all.
            Bytes rest(hello.size() - sizeof(head));
            answer = recv_exact(fd, rest.data(), rest.size(), 3000) &&
                             std::equal(rest.begin(), rest.end(), hello.begin() + 6)
                         ? Answer::echoed
                         : Answer::other;
        }
    }
    ::close(fd);
    return answer;
}

void set_personal_domain(Daemon& daemon, const std::string& name, std::string_view domain) {
    mtdd::control::UpdateUserRequest update;
    update.name = name;
    update.policy.tls_domain = std::string(domain);
    ASSERT_TRUE(daemon.services.store->update_user(update).ok());
}

} // namespace

TEST(HelloAdmission, ForeignOrMissingSniCostsNoHmac) {
    Daemon daemon(1, false);
    ASSERT_TRUE(daemon.services.add_user("alice", user_secret_hex(0)));
    ASSERT_TRUE(daemon.services.add_user("bob", user_secret_hex(1)));
    set_personal_domain(daemon, "bob", kFrontDomain);
    // Let the reactor see the snapshot with bob's domain.
    ASSERT_EQ(hello_from(daemon, "127.0.0.1", user_secret(0)), Answer::server_hello);
    ASSERT_TRUE(wait_for([&] {
        return hello_from(daemon, "127.0.0.1", user_secret(1), kFrontDomain) ==
               Answer::server_hello;
    }, 3000ms));

    const auto before = hmac_attempts(daemon);
    EXPECT_EQ(hello_from(daemon, "127.0.0.1", user_secret(0), "other.org"), Answer::closed);
    EXPECT_EQ(hello_from(daemon, "127.0.0.1", user_secret(0), ""), Answer::closed);
    EXPECT_EQ(hmac_attempts(daemon), before);

    // Our domain: only the keys allowed on it.
    A16 wrong{};
    wrong.fill(0x5a);
    EXPECT_EQ(hello_from(daemon, "127.0.0.1", wrong, kDomain), Answer::closed);
    EXPECT_EQ(hmac_attempts(daemon), before + 1);  // alice only
    EXPECT_EQ(hello_from(daemon, "127.0.0.1", wrong, kFrontDomain), Answer::closed);
    EXPECT_EQ(hmac_attempts(daemon), before + 2);  // bob only
    // A user's secret on another user's domain is not tried against itself.
    EXPECT_EQ(hello_from(daemon, "127.0.0.1", user_secret(0), kFrontDomain), Answer::closed);
    EXPECT_EQ(hmac_attempts(daemon), before + 3);
    // The prefilter is case-insensitive like the SNI check after it.
    EXPECT_EQ(hello_from(daemon, "127.0.0.1", user_secret(1), "FRONT.Example"),
              Answer::server_hello);
    EXPECT_EQ(hmac_attempts(daemon), before + 4);
}

TEST(HelloAdmission, WithoutAConfiguredDomainAnySniIsTried) {
    Daemon daemon(1, false, [](mtdd::Config& config) { config.tls_domain.clear(); });
    ASSERT_TRUE(daemon.services.add_user("alice", std::string(kSecretHex)));
    const auto before = hmac_attempts(daemon);
    EXPECT_EQ(hello_from(daemon, "127.0.0.1", secret_bytes(), "anything.org"),
              Answer::server_hello);
    EXPECT_EQ(hello_from(daemon, "127.0.0.1", secret_bytes(), ""), Answer::server_hello);
    EXPECT_EQ(hmac_attempts(daemon), before + 2);
}

TEST(HelloAdmission, UserLastSeenFromAnAddressOrPrefixIsTriedFirst) {
    Daemon daemon(1, false);
    constexpr std::uint8_t kUsers = 10;
    for (std::uint8_t i = 0; i < kUsers; ++i) {
        ASSERT_TRUE(daemon.services.add_user("u" + std::to_string(i), user_secret_hex(i)));
    }
    const A16 last = user_secret(kUsers - 1);  // last in snapshot order
    auto before = hmac_attempts(daemon);
    ASSERT_EQ(hello_from(daemon, "127.0.0.5", last), Answer::server_hello);
    EXPECT_EQ(hmac_attempts(daemon) - before, kUsers);

    before = hmac_attempts(daemon);
    ASSERT_EQ(hello_from(daemon, "127.0.0.5", last), Answer::server_hello);
    EXPECT_EQ(hmac_attempts(daemon) - before, 1U) << "address hint";

    before = hmac_attempts(daemon);
    ASSERT_EQ(hello_from(daemon, "127.0.0.6", last), Answer::server_hello);
    EXPECT_EQ(hmac_attempts(daemon) - before, 1U) << "/24 prefix hint";

    before = hmac_attempts(daemon);
    ASSERT_EQ(hello_from(daemon, "127.0.1.6", last), Answer::server_hello);
    EXPECT_EQ(hmac_attempts(daemon) - before, kUsers) << "another /24: no hint";

    // A hint that misses costs one HMAC, and the hinted key is not repeated
    // in the full scan; the new user then becomes the hint.
    before = hmac_attempts(daemon);
    ASSERT_EQ(hello_from(daemon, "127.0.0.5", user_secret(0)), Answer::server_hello);
    EXPECT_EQ(hmac_attempts(daemon) - before, 2U);
    before = hmac_attempts(daemon);
    A16 wrong{};
    wrong.fill(0x5a);
    EXPECT_EQ(hello_from(daemon, "127.0.0.5", wrong), Answer::closed);
    EXPECT_EQ(hmac_attempts(daemon) - before, kUsers) << "each key once";
    before = hmac_attempts(daemon);
    ASSERT_EQ(hello_from(daemon, "127.0.0.5", user_secret(0)), Answer::server_hello);
    EXPECT_EQ(hmac_attempts(daemon) - before, 1U);
    EXPECT_EQ(throttled(daemon), 0U);
}

TEST(HelloAdmission, ThrottledAddressGetsOnlyHintedKeysAndStaysIndistinguishable) {
    EchoBackend echo;
    AdmissionMaskingScope scope(echo.port());
    Daemon daemon(1, false, [](mtdd::Config& config) {
        config.masking = true;
        config.suspects = false;
    });
    constexpr std::uint8_t kUsers = 6;
    for (std::uint8_t i = 0; i < kUsers; ++i) {
        ASSERT_TRUE(daemon.services.add_user("u" + std::to_string(i), user_secret_hex(i)));
    }
    constexpr const char* kShared = "127.0.0.7";  // a CGNAT address: user + scanner
    ASSERT_EQ(hello_from(daemon, kShared, user_secret(2)), Answer::server_hello);

    A16 wrong{};
    wrong.fill(0x5a);
    // Comfortably over the threshold even if the window rolls mid-test.
    const std::uint32_t probes = mtdd::detail::kHelloThrottleFailures + 4;
    auto before = hmac_attempts(daemon);
    for (std::uint32_t i = 0; i < probes; ++i) {
        ASSERT_EQ(hello_from(daemon, kShared, wrong), Answer::echoed) << i;
    }
    // Throttling starts somewhere after kHelloThrottleFailures full scans.
    EXPECT_GE(hmac_attempts(daemon) - before,
              std::uint64_t{mtdd::detail::kHelloThrottleFailures} * kUsers);
    ASSERT_GE(throttled(daemon), 1U);

    // Throttled: one HMAC (the hinted user), and the same masked answer.
    const auto throttled_before = throttled(daemon);
    before = hmac_attempts(daemon);
    EXPECT_EQ(hello_from(daemon, kShared, wrong), Answer::echoed);
    EXPECT_EQ(hmac_attempts(daemon) - before, 1U);
    EXPECT_EQ(throttled(daemon), throttled_before + 1);
    // Foreign SNI from the throttled address: still nothing to try.
    before = hmac_attempts(daemon);
    EXPECT_EQ(hello_from(daemon, kShared, wrong, "other.org"), Answer::echoed);
    EXPECT_EQ(hmac_attempts(daemon) - before, 0U);

    // The real user behind the address still gets in.
    before = hmac_attempts(daemon);
    EXPECT_EQ(hello_from(daemon, kShared, user_secret(2)), Answer::server_hello);
    EXPECT_EQ(hmac_attempts(daemon) - before, 1U);
    // Another valid user from the throttled address is not tried (masked like
    // any failure); from a neighbour address it is.
    EXPECT_EQ(hello_from(daemon, kShared, user_secret(4)), Answer::echoed);
    EXPECT_EQ(hello_from(daemon, "127.0.0.8", user_secret(4)), Answer::server_hello);
    EXPECT_EQ(stat_counter(daemon.services.stats, "handshakes", "replay"), 0U);
    const auto metrics = daemon.services.stats.prometheus_text();
    EXPECT_NE(metrics.find("mtdd_handshake_throttled_total " + std::to_string(throttled(daemon)) +
                           "\n"),
              std::string::npos);
    EXPECT_NE(metrics.find("mtdd_handshake_hmac_attempts_total "), std::string::npos);
}

TEST(HelloAdmission, ClientClockSkewWindowFollowsTheConfig) {
    for (const std::uint32_t window : {120U, 600U, 0U}) {
        SCOPED_TRACE(window);
        Daemon daemon(1, false, [&](mtdd::Config& config) {
            config.client_clock_skew_seconds = window;
        });
        ASSERT_TRUE(daemon.services.add_user("alice", user_secret_hex(0)));
        const auto at = [&](std::int64_t skew) {
            const int fd = connect_loopback(daemon.port());
            EXPECT_GE(fd, 0);
            const Bytes hello = make_client_hello(
                user_secret(0), static_cast<std::uint32_t>(current_timestamp() - skew), kDomain,
                next_variant());
            std::uint8_t head[6]{};
            const bool ok = send_all(fd, hello) && recv_exact(fd, head, sizeof(head), 3000) &&
                            head[5] == 0x02;
            ::close(fd);
            return ok;
        };
        const auto skewed = [&] {
            std::uint64_t total = 0;
            for (const auto& [side, buckets] :
                 daemon.services.stats.snapshot().hello_clock_skew_total) {
                for (const auto& [bucket, value] : buckets) total += value;
            }
            return total;
        };
        EXPECT_TRUE(at(0));
        // Two seconds inside the edge (the test and the reactor read the clock
        // at slightly different times).
        if (window != 0) {
            EXPECT_TRUE(at(static_cast<std::int64_t>(window) - 2));
            EXPECT_TRUE(at(-static_cast<std::int64_t>(window) + 2));
            EXPECT_FALSE(at(static_cast<std::int64_t>(window) + 3));
            EXPECT_FALSE(at(-static_cast<std::int64_t>(window) - 3));
            EXPECT_EQ(skewed(), 2U);
        } else {
            EXPECT_TRUE(at(86400 * 30));
            EXPECT_TRUE(at(-86400 * 30));
            EXPECT_EQ(skewed(), 0U);
        }
    }
}

TEST(HelloAdmissionMaps, StayBoundedAndKeepTheNewestEntry) {
    mtdd::detail::BoundedIpMap<mtdd::detail::HelloHint> map(4096, 0x1234);
    EXPECT_EQ(map.capacity(), 4096U);
    EXPECT_EQ(map.find(mtdd::detail::IpKey{}), nullptr);
    for (std::uint32_t i = 0; i < 100000; ++i) {
        mtdd::detail::IpKey key{};
        std::memcpy(key.data() + 12, &i, sizeof(i));
        map.upsert(key).user = i + 1;
        ASSERT_NE(map.find(key), nullptr);
        EXPECT_EQ(map.find(key)->user, i + 1);
        ASSERT_LE(map.size(), map.capacity());
    }
    EXPECT_EQ(map.size(), map.capacity());
    // Rewriting an entry does not grow the map.
    mtdd::detail::IpKey last{};
    const std::uint32_t last_index = 99999;
    std::memcpy(last.data() + 12, &last_index, sizeof(last_index));
    map.upsert(last).user = 7;
    EXPECT_EQ(map.size(), map.capacity());
    EXPECT_EQ(map.find(last)->user, 7U);
}

TEST(HelloAdmissionMaps, PrefixKeysAreSlash24AndSlash56) {
    const auto v4 = mtdd::detail::hello_ip_key(
        mtdd::protocol::Endpoint::v4({192, 0, 2, 77}, 443));
    const auto v4_prefix = mtdd::detail::hello_prefix_key(v4);
    EXPECT_EQ(v4_prefix, mtdd::detail::hello_prefix_key(mtdd::detail::hello_ip_key(
                             mtdd::protocol::Endpoint::v4({192, 0, 2, 1}, 1))));
    EXPECT_NE(v4_prefix, mtdd::detail::hello_prefix_key(mtdd::detail::hello_ip_key(
                             mtdd::protocol::Endpoint::v4({192, 0, 3, 77}, 443))));
    EXPECT_EQ(v4_prefix[14], 2U);
    EXPECT_EQ(v4_prefix[15], 0U);

    std::array<std::uint8_t, 16> address{0x20, 0x01, 0x0d, 0xb8, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};
    const auto v6 = mtdd::detail::hello_ip_key(mtdd::protocol::Endpoint::v6(address, 443));
    auto same_56 = address;
    same_56[7] = 0xff;
    same_56[15] = 0xee;
    auto other_56 = address;
    other_56[6] ^= 1;
    EXPECT_EQ(mtdd::detail::hello_prefix_key(v6),
              mtdd::detail::hello_prefix_key(
                  mtdd::detail::hello_ip_key(mtdd::protocol::Endpoint::v6(same_56, 1))));
    EXPECT_NE(mtdd::detail::hello_prefix_key(v6),
              mtdd::detail::hello_prefix_key(
                  mtdd::detail::hello_ip_key(mtdd::protocol::Endpoint::v6(other_56, 1))));
}
