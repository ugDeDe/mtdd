// PROXY protocol header (HAProxy v1 text / v2 binary) sent by a trusted front
// (load balancer, SNI router) ahead of the client's bytes. Pure functions of
// the received bytes: no sockets, no runtime state.
#include "mtdd/protocol.hpp"

#include <arpa/inet.h>

#include <algorithm>
#include <array>
#include <string>
#include <string_view>

namespace mtdd::protocol {
namespace {

constexpr std::array<std::uint8_t, 12> kV2Signature = {0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D,
                                                       0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A};
constexpr std::size_t kV2Prefix = 16;
constexpr std::string_view kV1Prefix = "PROXY ";
// Enough for the shortest complete header of either version ("PROXY
// UNKNOWN\r\n" is 15 bytes) and exactly the fixed v2 prefix.
constexpr std::size_t kFirstRead = 16;

ProxyHeaderScan need(std::size_t want) {
  ProxyHeaderScan out;
  out.want = want;
  return out;
}

ProxyHeaderScan invalid() {
  ProxyHeaderScan out;
  out.status = ProxyHeaderScan::Status::Invalid;
  return out;
}

ProxyHeaderScan ok(std::size_t length, std::optional<Endpoint> source) {
  ProxyHeaderScan out;
  out.status = ProxyHeaderScan::Status::Ok;
  out.length = length;
  out.source = std::move(source);
  return out;
}

// Decimal port, 1..5 digits, no sign, 0..65535.
std::optional<std::uint16_t> parse_port(std::string_view text) {
  if (text.empty() || text.size() > 5) return std::nullopt;
  if (text.size() > 1 && text.front() == '0') return std::nullopt;
  std::uint32_t value = 0;
  for (const char c : text) {
    if (c < '0' || c > '9') return std::nullopt;
    value = value * 10U + static_cast<std::uint32_t>(c - '0');
  }
  if (value > 65535U) return std::nullopt;
  return static_cast<std::uint16_t>(value);
}

std::optional<Endpoint> parse_address(std::string_view text, bool v6, std::uint16_t port) {
  if (text.empty() || text.size() > 45) return std::nullopt;
  const std::string address(text);
  if (v6) {
    std::array<std::uint8_t, 16> bytes{};
    if (::inet_pton(AF_INET6, address.c_str(), bytes.data()) != 1) return std::nullopt;
    return Endpoint::v6(bytes, port);
  }
  std::array<std::uint8_t, 4> bytes{};
  if (::inet_pton(AF_INET, address.c_str(), bytes.data()) != 1) return std::nullopt;
  return Endpoint::v4(bytes, port);
}

// The line without its CRLF: "PROXY TCP4 src dst sport dport" or
// "PROXY UNKNOWN[ anything]".
ProxyHeaderScan parse_v1_line(std::string_view line, std::size_t length) {
  line.remove_prefix(kV1Prefix.size());
  if (line == "UNKNOWN" || line.starts_with("UNKNOWN ")) return ok(length, std::nullopt);
  bool v6 = false;
  if (line.starts_with("TCP4 ")) {
    v6 = false;
  } else if (line.starts_with("TCP6 ")) {
    v6 = true;
  } else {
    return invalid();
  }
  line.remove_prefix(5);
  std::array<std::string_view, 4> fields{};
  for (std::size_t i = 0; i < fields.size(); ++i) {
    const std::size_t space = line.find(' ');
    if (i + 1 < fields.size()) {
      if (space == std::string_view::npos) return invalid();
      fields[i] = line.substr(0, space);
      line.remove_prefix(space + 1);
    } else {
      if (space != std::string_view::npos) return invalid();
      fields[i] = line;
    }
  }
  const auto source_port = parse_port(fields[2]);
  const auto destination_port = parse_port(fields[3]);
  if (!source_port || !destination_port || *source_port == 0) return invalid();
  auto source = parse_address(fields[0], v6, *source_port);
  if (!source || !parse_address(fields[1], v6, *destination_port)) return invalid();
  return ok(length, std::move(source));
}

ProxyHeaderScan scan_v1(std::span<const std::uint8_t> wire) {
  const std::size_t prefix = std::min(wire.size(), kV1Prefix.size());
  for (std::size_t i = 0; i < prefix; ++i) {
    if (wire[i] != static_cast<std::uint8_t>(kV1Prefix[i])) return invalid();
  }
  const std::size_t limit = std::min(wire.size(), kProxyHeaderV1Max);
  for (std::size_t i = 0; i < limit; ++i) {
    const std::uint8_t c = wire[i];
    if (c == '\r') {
      if (i + 1 < wire.size() && wire[i + 1] != '\n') return invalid();
      continue;
    }
    if (c == '\n') {
      if (i == 0 || wire[i - 1] != '\r' || i + 1 < kV1Prefix.size() + 2) return invalid();
      const std::string_view line(reinterpret_cast<const char*>(wire.data()), i - 1);
      return parse_v1_line(line, i + 1);
    }
    if (c < 0x20 || c > 0x7e) return invalid();
  }
  if (wire.size() >= kProxyHeaderV1Max) return invalid();
  return need(std::max(kProxyHeaderV1Max - wire.size(), std::size_t{1}));
}

std::uint16_t be16(std::span<const std::uint8_t> wire, std::size_t pos) {
  return static_cast<std::uint16_t>((static_cast<unsigned>(wire[pos]) << 8U) | wire[pos + 1]);
}

ProxyHeaderScan scan_v2(std::span<const std::uint8_t> wire) {
  const std::size_t prefix = std::min(wire.size(), kV2Signature.size());
  if (!std::equal(wire.begin(), wire.begin() + static_cast<std::ptrdiff_t>(prefix),
                  kV2Signature.begin())) {
    return invalid();
  }
  // Version 2, command LOCAL (0) or PROXY (1).
  if (wire.size() > 12 && (wire[12] >> 4U) != 2U) return invalid();
  if (wire.size() > 12 && (wire[12] & 0x0FU) > 1U) return invalid();
  if (wire.size() < kV2Prefix) return need(kV2Prefix - wire.size());
  const std::size_t total = kV2Prefix + be16(wire, 14);
  if (total > kProxyHeaderV2Max) return invalid();
  if (wire.size() < total) return need(total - wire.size());

  const bool local = (wire[12] & 0x0FU) == 0U;
  if (local) return ok(total, std::nullopt);
  const std::size_t body = total - kV2Prefix;
  switch (wire[13]) {
    case 0x11: {  // TCP over IPv4
      if (body < 12) return invalid();
      const std::uint16_t port = be16(wire, 24);
      if (port == 0) return invalid();
      return ok(total, Endpoint::v4({wire[16], wire[17], wire[18], wire[19]}, port));
    }
    case 0x21: {  // TCP over IPv6
      if (body < 36) return invalid();
      const std::uint16_t port = be16(wire, 48);
      if (port == 0) return invalid();
      std::array<std::uint8_t, 16> address{};
      std::copy_n(wire.begin() + 16, address.size(), address.begin());
      return ok(total, Endpoint::v6(address, port));
    }
    default:
      // UNSPEC, UDP or UNIX: the spec lets the receiver keep the socket peer.
      return ok(total, std::nullopt);
  }
}

}  // namespace

ProxyHeaderScan scan_proxy_header(std::span<const std::uint8_t> wire) {
  if (wire.empty()) return need(kFirstRead);
  if (wire[0] == static_cast<std::uint8_t>('P')) return scan_v1(wire);
  if (wire[0] == kV2Signature[0]) return scan_v2(wire);
  return invalid();
}

}  // namespace mtdd::protocol
