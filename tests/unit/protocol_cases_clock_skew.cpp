// FakeTLS ClientHello whose HMAC matches but whose timestamp is outside the
// window: ClockSkew reports the client's timestamp (so the caller can measure
// the skew) and nothing else; a wrong secret reports nothing at all.
#include "../support/protocol_fixture.hpp"

namespace mtdd::protocol {

namespace {

constexpr std::uint32_t kWindow = 120;

Bytes hello_at(const A16& secret, std::int64_t client_ts) {
  return make_client_hello(secret, static_cast<std::uint32_t>(client_ts), 0x001d, 32, 0x1301,
                           "example.com");
}

void expect_nothing_secret(const ClientHelloInfo& info) {
  EXPECT_EQ(info.digest, A32{});
  EXPECT_EQ(info.canonical_hmac, A32{});
  EXPECT_EQ(info.session_id, A32{});
  EXPECT_EQ(info.secret, A16{});
  EXPECT_TRUE(info.server_name.empty());
}

}  // namespace

TEST(FakeTlsClockSkew, InsideTheWindowOnBothSidesIsOk) {
  for (const std::int64_t skew : {-static_cast<std::int64_t>(kWindow), std::int64_t{0},
                                  static_cast<std::int64_t>(kWindow)}) {
    SCOPED_TRACE(skew);
    const Bytes rec = hello_at(kSecret, kNow - skew);
    ClientHelloInfo info;
    EXPECT_EQ(validate_client_hello(rec, kSecret, kNow, kWindow, info), HelloStatus::Ok);
    EXPECT_EQ(info.timestamp, static_cast<std::uint32_t>(kNow - skew));
  }
}

TEST(FakeTlsClockSkew, JustOutsideTheWindowReportsOnlyTheTimestamp) {
  // skew = server clock - client timestamp: positive = client clock behind.
  for (const std::int64_t skew : {-static_cast<std::int64_t>(kWindow) - 1,
                                  static_cast<std::int64_t>(kWindow) + 1, std::int64_t{-86400},
                                  std::int64_t{86400}}) {
    SCOPED_TRACE(skew);
    const Bytes rec = hello_at(kSecret, kNow - skew);
    ClientHelloInfo info;
    ASSERT_EQ(validate_client_hello(rec, kSecret, kNow, kWindow, info), HelloStatus::ClockSkew);
    EXPECT_EQ(kNow - static_cast<std::int64_t>(info.timestamp), skew);
    expect_nothing_secret(info);
  }
}

TEST(FakeTlsClockSkew, MultiKeyClockSkewReportsTheMatchedIndexAndTimestamp) {
  A16 other{};
  other.fill(0x77);
  const crypto::HmacSha256Key bad_key(other);
  const crypto::HmacSha256Key good_key(kSecret);
  const crypto::HmacSha256Key* keys[] = {&bad_key, nullptr, &good_key};
  const Bytes rec = hello_at(kSecret, kNow + 600);  // client clock 10 min ahead
  ClientHelloInfo info;
  std::size_t matched = 99;
  ASSERT_EQ(validate_client_hello(rec, keys, kNow, kWindow, info, matched),
            HelloStatus::ClockSkew);
  EXPECT_EQ(matched, 2U);
  EXPECT_EQ(kNow - static_cast<std::int64_t>(info.timestamp), -600);
  expect_nothing_secret(info);
}

TEST(FakeTlsClockSkew, WrongSecretWithAWildTimestampReportsNothing) {
  A16 wrong{};
  wrong.fill(0x5a);
  const crypto::HmacSha256Key wrong_key(wrong);
  const crypto::HmacSha256Key* keys[] = {&wrong_key};
  for (const std::int64_t skew : {std::int64_t{-100000}, std::int64_t{0}, std::int64_t{100000}}) {
    SCOPED_TRACE(skew);
    // Signed with kSecret, checked against another key.
    const Bytes rec = hello_at(kSecret, kNow - skew);
    ClientHelloInfo info;
    EXPECT_EQ(validate_client_hello(rec, wrong, kNow, kWindow, info),
              HelloStatus::Unauthenticated);
    EXPECT_EQ(info.timestamp, 0U);
    expect_nothing_secret(info);
    std::size_t matched = 0;
    EXPECT_EQ(validate_client_hello(rec, keys, kNow, kWindow, info, matched),
              HelloStatus::Unauthenticated);
    EXPECT_EQ(info.timestamp, 0U);
    expect_nothing_secret(info);
  }
}

TEST(FakeTlsClockSkew, CustomWindowBoundariesAreInclusive) {
  constexpr std::uint32_t kCustom = 300;
  for (const std::int64_t skew : {-std::int64_t{kCustom}, std::int64_t{kCustom}}) {
    SCOPED_TRACE(skew);
    ClientHelloInfo info;
    EXPECT_EQ(validate_client_hello(hello_at(kSecret, kNow - skew), kSecret, kNow, kCustom, info),
              HelloStatus::Ok);
    EXPECT_EQ(validate_client_hello(hello_at(kSecret, kNow - skew - (skew > 0 ? 1 : -1)), kSecret,
                                    kNow, kCustom, info),
              HelloStatus::ClockSkew);
  }
}

TEST(FakeTlsClockSkew, ZeroWindowIgnoresTheClientTimestamp) {
  for (const std::int64_t client_ts : {std::int64_t{0}, std::int64_t{1}, kNow - 86400 * 365,
                                       kNow + 86400 * 365, std::int64_t{0xffffffff}}) {
    SCOPED_TRACE(client_ts);
    const Bytes rec = hello_at(kSecret, client_ts);
    ClientHelloInfo info;
    EXPECT_EQ(validate_client_hello(rec, kSecret, kNow, 0, info), HelloStatus::Ok);
    EXPECT_EQ(info.timestamp, static_cast<std::uint32_t>(client_ts));
    EXPECT_EQ(info.secret, kSecret);
  }
  // Still authenticated: a wrong secret is not let through by a zero window.
  A16 wrong{};
  wrong.fill(0x5a);
  ClientHelloInfo info;
  EXPECT_EQ(validate_client_hello(hello_at(kSecret, kNow), wrong, kNow, 0, info),
            HelloStatus::Unauthenticated);
}

TEST(FakeTlsClockSkew, ConnectionHonoursZeroWindowAndEnforceFlag) {
  const Bytes rec = hello_at(kSecret, kNow - 5000);
  const auto run = [&](std::uint32_t window, bool enforce) {
    FakeTlsConnection::Config cfg;
    cfg.secret = kSecret;
    CountingRng rng;
    cfg.random = rng.fn();
    cfg.clock = [] { return kNow; };
    cfg.skew_seconds = window;
    cfg.enforce_time_skew = enforce;
    FakeTlsConnection conn(cfg);
    std::vector<std::uint8_t> to_client, plain;
    return conn.feed(rec, to_client, plain);
  };
  EXPECT_EQ(run(120, true), Status::ProtocolError);
  EXPECT_EQ(run(0, true), Status::Ok);
  EXPECT_EQ(run(120, false), Status::Ok);
  EXPECT_EQ(run(6000, true), Status::Ok);
}

TEST(FakeTlsKeySelector, SelectorSeesTheSniOnceAndIndexesItsOwnSpan) {
  A16 other{};
  other.fill(0x77);
  const crypto::HmacSha256Key bad_key(other);
  const crypto::HmacSha256Key good_key(kSecret);
  const crypto::HmacSha256Key* chosen[] = {&bad_key, &good_key};
  int calls = 0;
  std::string seen;
  const HelloKeySelector select = [&](std::string_view sni) {
    ++calls;
    seen = std::string(sni);
    return std::span<const crypto::HmacSha256Key* const>(chosen);
  };
  const Bytes rec =
      make_client_hello(kSecret, static_cast<std::uint32_t>(kNow), 0x001d, 32, 0x1301, "Example.COM");
  ClientHelloInfo info;
  std::size_t matched = 99;
  ASSERT_EQ(validate_client_hello(rec, select, kNow, kWindow, info, matched), HelloStatus::Ok);
  EXPECT_EQ(calls, 1);
  EXPECT_EQ(seen, "Example.COM");  // as sent: the caller normalizes
  EXPECT_EQ(matched, 1U);
  EXPECT_EQ(info.server_name, "Example.COM");

  // No SNI: an empty name; an empty selection authenticates nothing.
  const Bytes bare = make_client_hello(kSecret, static_cast<std::uint32_t>(kNow));
  const HelloKeySelector none = [&](std::string_view sni) {
    ++calls;
    seen = std::string(sni);
    return std::span<const crypto::HmacSha256Key* const>();
  };
  EXPECT_EQ(validate_client_hello(bare, none, kNow, kWindow, info, matched),
            HelloStatus::Unauthenticated);
  EXPECT_EQ(calls, 2);
  EXPECT_TRUE(seen.empty());
}

TEST(FakeTlsKeySelector, MalformedHelloIsInvalidBeforeAnyKeyIsChosen) {
  int calls = 0;
  const HelloKeySelector select = [&](std::string_view) {
    ++calls;
    return std::span<const crypto::HmacSha256Key* const>();
  };
  // No TLS 1.3 cipher suite: rejected on structure, whatever the secret.
  const Bytes no_tls13 = make_client_hello(kSecret, static_cast<std::uint32_t>(kNow), 0x001d, 32,
                                           0x1301, "example.com", false);
  ClientHelloInfo info;
  std::size_t matched = 0;
  EXPECT_EQ(validate_client_hello(no_tls13, select, kNow, kWindow, info, matched),
            HelloStatus::Invalid);
  // A valid hello with one byte dropped from its last extension.
  Bytes cut = hello_at(kSecret, kNow);
  cut.pop_back();
  const std::size_t body = cut.size() - 5;
  cut[3] = static_cast<std::uint8_t>(body >> 8);
  cut[4] = static_cast<std::uint8_t>(body);
  const std::size_t handshake = body - 4;
  cut[6] = static_cast<std::uint8_t>(handshake >> 16);
  cut[7] = static_cast<std::uint8_t>(handshake >> 8);
  cut[8] = static_cast<std::uint8_t>(handshake);
  EXPECT_EQ(validate_client_hello(cut, select, kNow, kWindow, info, matched),
            HelloStatus::Invalid);
  EXPECT_EQ(calls, 0);
}

}  // namespace mtdd::protocol
