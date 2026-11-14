// SOCKS5 CONNECT client handshake (Socks5Client): RFC 1928 + RFC 1929.
#include "../support/protocol_fixture.hpp"

namespace mtdd::protocol {

namespace {

using SocksStatus = Socks5Client::Status;

const Endpoint kTarget = Endpoint::v4({149, 154, 175, 50}, 8888);

// Feeds `reply` the way the runtime reads it: never more than want().
SocksStatus feed_by_want(Socks5Client& client, const Bytes& reply, Bytes& sent) {
  std::size_t pos = 0;
  while (client.status() == SocksStatus::NeedMore && pos < reply.size()) {
    const std::size_t take = std::min(client.want(), reply.size() - pos);
    EXPECT_GE(take, 1U);
    client.feed(std::span<const std::uint8_t>(reply).subspan(pos, take), sent);
    pos += take;
  }
  EXPECT_EQ(pos, reply.size());
  return client.status();
}

}  // namespace

TEST(Socks5, NoAuthConnectReportsTheBoundAddress) {
  Socks5Client client(kTarget);
  EXPECT_EQ(client.want(), 0U);  // nothing to read before the greeting
  EXPECT_EQ(client.start(), (Bytes{5, 1, 0}));
  Bytes sent;
  ASSERT_EQ(client.feed(Bytes{5, 0}, sent), SocksStatus::NeedMore);
  EXPECT_EQ(sent, (Bytes{5, 1, 0, 1, 149, 154, 175, 50, 0x22, 0xb8}));
  sent.clear();
  ASSERT_EQ(feed_by_want(client, Bytes{5, 0, 0, 1, 203, 0, 113, 9, 0xc3, 0x50}, sent), SocksStatus::Done);
  EXPECT_TRUE(sent.empty());
  ASSERT_TRUE(client.bound());
  EXPECT_EQ(*client.bound(), Endpoint::v4({203, 0, 113, 9}, 50000));
  EXPECT_EQ(client.want(), 0U);
}

TEST(Socks5, UsernamePasswordAndIpv6Target) {
  std::array<std::uint8_t, 16> v6{0x20, 0x01, 0x0b, 0x28};
  v6[15] = 0x0a;
  Socks5Client client(Endpoint::v6(v6, 443), "user", "secret");
  EXPECT_EQ(client.start(), (Bytes{5, 1, 2}));
  Bytes sent;
  ASSERT_EQ(client.feed(Bytes{5, 2}, sent), SocksStatus::NeedMore);
  EXPECT_EQ(sent, cat({Bytes{1, 4}, Bytes{'u', 's', 'e', 'r'}, Bytes{6},
                      Bytes{'s', 'e', 'c', 'r', 'e', 't'}}));
  sent.clear();
  ASSERT_EQ(client.feed(Bytes{1, 0}, sent), SocksStatus::NeedMore);
  Bytes expected{5, 1, 0, 4};
  expected.insert(expected.end(), v6.begin(), v6.end());
  expected.insert(expected.end(), {0x01, 0xbb});
  EXPECT_EQ(sent, expected);
  sent.clear();
  Bytes reply{5, 0, 0, 4};
  reply.insert(reply.end(), v6.begin(), v6.end());
  reply.insert(reply.end(), {0x9c, 0x40});
  ASSERT_EQ(feed_by_want(client, reply, sent), SocksStatus::Done);
  ASSERT_TRUE(client.bound());
  EXPECT_EQ(*client.bound(), Endpoint::v6(v6, 40000));
}

TEST(Socks5, DomainBoundAddressCompletesWithoutAnEndpoint) {
  Socks5Client client(kTarget);
  (void)client.start();
  Bytes sent;
  client.feed(Bytes{5, 0}, sent);
  const Bytes reply{5, 0, 0, 3, 4, 'h', 'o', 's', 't', 0x00, 0x50};
  ASSERT_EQ(feed_by_want(client, reply, sent), SocksStatus::Done);
  EXPECT_FALSE(client.bound());
}

TEST(Socks5, FailuresAreReported) {
  struct Case {
    const char* name;
    std::string user;
    Bytes method;
    Bytes auth;
    Bytes head;
    const char* error;
  };
  const std::vector<Case> cases = {
      {"socks4 server", "", {4, 0}, {}, {}, "not a SOCKS5 server"},
      {"no acceptable method", "", {5, 0xff}, {}, {}, "none of the offered"},
      {"method not offered", "", {5, 2}, {}, {}, "not offered"},
      {"auth rejected", "u", {5, 2}, {1, 1}, {}, "authentication failed"},
      {"connect refused", "", {5, 0}, {}, {5, 5, 0, 1}, "connection refused"},
      {"bad reply version", "", {5, 0}, {}, {4, 0, 0, 1}, "not a SOCKS5 reply"},
      {"bad address type", "", {5, 0}, {}, {5, 0, 0, 9}, "unknown address type"},
  };
  for (const auto& c : cases) {
    SCOPED_TRACE(c.name);
    Socks5Client client(kTarget, c.user, c.user.empty() ? "" : "p");
    (void)client.start();
    Bytes sent;
    SocksStatus status = client.feed(c.method, sent);
    if (!c.auth.empty()) status = client.feed(c.auth, sent);
    if (!c.head.empty()) status = client.feed(c.head, sent);
    EXPECT_EQ(status, SocksStatus::Failed);
    EXPECT_NE(client.error().find(c.error), std::string_view::npos) << client.error();
    EXPECT_EQ(client.want(), 0U);
  }
}

TEST(Socks5, ReadingPastTheReplyIsAFailure) {
  Socks5Client client(kTarget);
  (void)client.start();
  Bytes sent;
  client.feed(Bytes{5, 0}, sent);
  EXPECT_EQ(client.feed(Bytes{5, 0, 0, 1, 1, 2, 3, 4, 0, 80, 0x16}, sent), SocksStatus::Failed);
}

TEST(Socks5, InvalidCredentialsAreRejectedAtConstruction) {
  EXPECT_THROW(Socks5Client(kTarget, "user", ""), std::invalid_argument);
  EXPECT_THROW(Socks5Client(kTarget, std::string(256, 'u'), "p"), std::invalid_argument);
  EXPECT_THROW(Socks5Client(Endpoint::v4({1, 2, 3, 4}, 0)), std::invalid_argument);
}

}  // namespace mtdd::protocol
