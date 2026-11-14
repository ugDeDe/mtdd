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

}  // namespace mtdd::protocol
