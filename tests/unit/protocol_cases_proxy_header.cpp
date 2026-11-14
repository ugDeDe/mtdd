// PROXY protocol header (HAProxy v1 text / v2 binary) in front of the client
// stream: scan_proxy_header() classifies a received prefix.
#include "../support/protocol_fixture.hpp"

namespace mtdd::protocol {

namespace {

using Scan = ProxyHeaderScan::Status;

Bytes text(std::string_view value) { return Bytes(value.begin(), value.end()); }

const Bytes kV2Signature{0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A};

Bytes v2(std::uint8_t ver_cmd, std::uint8_t family, const Bytes& body) {
  Bytes out = kV2Signature;
  out.push_back(ver_cmd);
  out.push_back(family);
  out.push_back(static_cast<std::uint8_t>(body.size() >> 8));
  out.push_back(static_cast<std::uint8_t>(body.size()));
  out.insert(out.end(), body.begin(), body.end());
  return out;
}

Bytes v2_tcp4_body(std::uint16_t source_port) {
  return {192, 0, 2, 1, 198, 51, 100, 2, static_cast<std::uint8_t>(source_port >> 8),
          static_cast<std::uint8_t>(source_port), 0x01, 0xbb};
}

// Feeds `wire` the way the runtime reads it: never more than `want` at once.
ProxyHeaderScan feed_by_want(const Bytes& wire, std::size_t& consumed) {
  Bytes have;
  for (;;) {
    const auto scan = scan_proxy_header(have);
    if (scan.status != Scan::NeedMoreData) {
      consumed = have.size();
      return scan;
    }
    EXPECT_GE(scan.want, 1U);
    const std::size_t take = std::min(scan.want, wire.size() - have.size());
    if (take == 0) {
      consumed = have.size();
      return scan;
    }
    have.insert(have.end(), wire.begin() + static_cast<std::ptrdiff_t>(have.size()),
                wire.begin() + static_cast<std::ptrdiff_t>(have.size() + take));
  }
}

}  // namespace

TEST(ProxyHeader, V1Tcp4AndTcp6) {
  const auto four = scan_proxy_header(text("PROXY TCP4 192.0.2.1 198.51.100.2 40000 443\r\nrest"));
  ASSERT_EQ(four.status, Scan::Ok);
  EXPECT_EQ(four.length, 45U);
  ASSERT_TRUE(four.source);
  EXPECT_EQ(*four.source, Endpoint::v4({192, 0, 2, 1}, 40000));

  const auto six = scan_proxy_header(text("PROXY TCP6 2001:db8::1 ::1 65535 1\r\n"));
  ASSERT_EQ(six.status, Scan::Ok);
  ASSERT_TRUE(six.source);
  std::array<std::uint8_t, 16> address{0x20, 0x01, 0x0d, 0xb8};
  address[15] = 1;
  EXPECT_EQ(*six.source, Endpoint::v6(address, 65535));
}

TEST(ProxyHeader, V1UnknownKeepsTheSocketPeer) {
  for (const char* line : {"PROXY UNKNOWN\r\n", "PROXY UNKNOWN ffff::1 ffff::2 1 2\r\n"}) {
    const auto scan = scan_proxy_header(text(line));
    ASSERT_EQ(scan.status, Scan::Ok) << line;
    EXPECT_EQ(scan.length, std::string_view(line).size());
    EXPECT_FALSE(scan.source);
  }
}

TEST(ProxyHeader, V1MalformedIsInvalid) {
  for (const char* line : {
           "PROXY TCP4 192.0.2.1 198.51.100.2 0 443\r\n",       // source port 0
           "PROXY TCP4 192.0.2.1 198.51.100.2 040000 443\r\n",  // leading zero
           "PROXY TCP4 192.0.2.1 198.51.100.2 65536 443\r\n",
           "PROXY TCP4 2001:db8::1 ::1 1 2\r\n",               // wrong family
           "PROXY TCP6 192.0.2.1 198.51.100.2 1 2\r\n",
           "PROXY TCP4 192.0.2.1  198.51.100.2 1 2\r\n",       // double space
           "PROXY TCP4 192.0.2.1 198.51.100.2 1 2 3\r\n",
           "PROXY TCP4 192.0.2.1 198.51.100.2 1\r\n",
           "PROXY UDP4 192.0.2.1 198.51.100.2 1 2\r\n",
           "PROXY TCP4 192.0.2.1 198.51.100.2 1 2\n",          // bare LF
           "PROXY TCP4 192.0.2.1\r198.51.100.2 1 2\r\n",       // CR inside
           "PROXY\r\n",
           "proxy TCP4 192.0.2.1 198.51.100.2 1 2\r\n",
           "GET / HTTP/1.1\r\n"}) {
    EXPECT_EQ(scan_proxy_header(text(line)).status, Scan::Invalid) << line;
  }
  // No CRLF within 107 bytes.
  Bytes long_line = text("PROXY UNKNOWN ");
  long_line.resize(kProxyHeaderV1Max, 'x');
  EXPECT_EQ(scan_proxy_header(long_line).status, Scan::Invalid);
  // A binary byte in the line.
  Bytes binary = text("PROXY TCP4 ");
  binary.push_back(0x16);
  EXPECT_EQ(scan_proxy_header(binary).status, Scan::Invalid);
}

TEST(ProxyHeader, V1PrefixWaitsWithinTheV1Bound) {
  const auto empty = scan_proxy_header({});
  ASSERT_EQ(empty.status, Scan::NeedMoreData);
  EXPECT_EQ(empty.want, 16U);
  const Bytes partial = text("PROXY TCP4 192.0.2.1 ");
  const auto scan = scan_proxy_header(partial);
  ASSERT_EQ(scan.status, Scan::NeedMoreData);
  EXPECT_EQ(partial.size() + scan.want, kProxyHeaderV1Max);
  // A wrong prefix is refused at its first byte.
  EXPECT_EQ(scan_proxy_header(text("PROXX")).status, Scan::Invalid);
  EXPECT_EQ(scan_proxy_header(Bytes{0x16}).status, Scan::Invalid);
}

TEST(ProxyHeader, V2Tcp4Tcp6AndTlvs) {
  Bytes body = v2_tcp4_body(40000);
  const Bytes tlv{0x04, 0x00, 0x03, 'a', 'b', 'c'};  // PP2_TYPE_NOOP
  body.insert(body.end(), tlv.begin(), tlv.end());
  const Bytes four = cat({v2(0x21, 0x11, body), text("tail")});
  const auto scan4 = scan_proxy_header(four);
  ASSERT_EQ(scan4.status, Scan::Ok);
  EXPECT_EQ(scan4.length, 16U + body.size());
  ASSERT_TRUE(scan4.source);
  EXPECT_EQ(*scan4.source, Endpoint::v4({192, 0, 2, 1}, 40000));

  Bytes body6(36, 0);
  body6[0] = 0x20;
  body6[1] = 0x01;
  body6[15] = 9;
  body6[32] = 0x9c;
  body6[33] = 0x41;  // 40001
  const auto scan6 = scan_proxy_header(v2(0x21, 0x21, body6));
  ASSERT_EQ(scan6.status, Scan::Ok);
  ASSERT_TRUE(scan6.source);
  std::array<std::uint8_t, 16> address{0x20, 0x01};
  address[15] = 9;
  EXPECT_EQ(*scan6.source, Endpoint::v6(address, 40001));
}

TEST(ProxyHeader, V2LocalAndOtherFamiliesKeepTheSocketPeer) {
  const auto local = scan_proxy_header(v2(0x20, 0x00, {}));
  ASSERT_EQ(local.status, Scan::Ok);
  EXPECT_EQ(local.length, 16U);
  EXPECT_FALSE(local.source);
  // LOCAL ignores whatever address block a front sends along.
  EXPECT_FALSE(scan_proxy_header(v2(0x20, 0x11, v2_tcp4_body(1))).source);
  for (const std::uint8_t family : {std::uint8_t{0x00}, std::uint8_t{0x12}, std::uint8_t{0x22},
                                    std::uint8_t{0x31}}) {
    const auto scan = scan_proxy_header(v2(0x21, family, Bytes(216, 0)));
    ASSERT_EQ(scan.status, Scan::Ok) << int(family);
    EXPECT_FALSE(scan.source);
  }
}

TEST(ProxyHeader, V2MalformedIsInvalid) {
  EXPECT_EQ(scan_proxy_header(v2(0x11, 0x11, v2_tcp4_body(1))).status, Scan::Invalid);  // v1 bits
  EXPECT_EQ(scan_proxy_header(v2(0x22, 0x11, v2_tcp4_body(1))).status, Scan::Invalid);  // cmd 2
  EXPECT_EQ(scan_proxy_header(v2(0x21, 0x11, v2_tcp4_body(0))).status, Scan::Invalid);  // port 0
  EXPECT_EQ(scan_proxy_header(v2(0x21, 0x11, Bytes(11, 1))).status, Scan::Invalid);     // short
  EXPECT_EQ(scan_proxy_header(v2(0x21, 0x21, Bytes(35, 1))).status, Scan::Invalid);
  Bytes oversized = v2(0x21, 0x11, v2_tcp4_body(1));
  oversized[14] = 0x08;  // 2048 + 12 > the limit
  oversized[15] = 0x0c;
  EXPECT_EQ(scan_proxy_header(oversized).status, Scan::Invalid);
  Bytes signature = kV2Signature;
  signature[7] = 0x00;
  EXPECT_EQ(scan_proxy_header(signature).status, Scan::Invalid);
  // Version/command are refused as soon as their byte arrives.
  Bytes early = kV2Signature;
  early.push_back(0x31);
  EXPECT_EQ(scan_proxy_header(early).status, Scan::Invalid);
}

TEST(ProxyHeader, V2IsReadExactlyAndV1NeverPastItsBound) {
  Bytes body = v2_tcp4_body(5000);
  body.resize(300, 0x04);
  const Bytes header = v2(0x21, 0x11, body);
  const Bytes stream = cat({header, Bytes(500, 0x16)});
  std::size_t consumed = 0;
  const auto scan = feed_by_want(stream, consumed);
  ASSERT_EQ(scan.status, Scan::Ok);
  EXPECT_EQ(consumed, header.size());  // not one stream byte read
  EXPECT_EQ(scan.length, header.size());

  const Bytes line = text("PROXY UNKNOWN\r\n");
  const auto v1 = feed_by_want(cat({line, Bytes(500, 0x16)}), consumed);
  ASSERT_EQ(v1.status, Scan::Ok);
  EXPECT_EQ(v1.length, line.size());
  EXPECT_LE(consumed, kProxyHeaderV1Max);
}

TEST(ProxyHeader, ByteByByteAgreesWithAllAtOnce) {
  const std::vector<Bytes> wires = {
      text("PROXY TCP4 192.0.2.1 198.51.100.2 40000 443\r\n"),
      text("PROXY TCP6 2001:db8::1 ::1 65535 1\r\n"),
      v2(0x21, 0x11, v2_tcp4_body(7)),
      v2(0x20, 0x00, {}),
  };
  for (const auto& wire : wires) {
    const auto whole = scan_proxy_header(wire);
    ASSERT_EQ(whole.status, Scan::Ok);
    for (std::size_t n = 0; n < wire.size(); ++n) {
      const auto partial =
          scan_proxy_header(std::span<const std::uint8_t>(wire).first(n));
      ASSERT_EQ(partial.status, Scan::NeedMoreData) << n;
    }
  }
}

}  // namespace mtdd::protocol
