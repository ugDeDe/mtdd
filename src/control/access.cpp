// Source-address allowlists for the control and metrics listeners.
//
// Networks are stored as IPv4-mapped IPv6 so one comparison covers both
// families and dual-stack peers (::ffff:a.b.c.d) match plain IPv4 entries.
#include "http_internal.hpp"

#include <event2/http.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <charconv>
#include <cstring>

namespace mtdd::control::detail {
namespace {

std::array<uint8_t, 16> mapped_v4(const in_addr& address) {
  std::array<uint8_t, 16> out{};
  out[10] = 0xff;
  out[11] = 0xff;
  std::memcpy(out.data() + 12, &address, 4);
  return out;
}

bool prefix_matches(const std::array<uint8_t, 16>& a,
                    const std::array<uint8_t, 16>& b, unsigned prefix) {
  const unsigned full = prefix / 8;
  if (std::memcmp(a.data(), b.data(), full) != 0) return false;
  const unsigned rest = prefix % 8;
  if (rest == 0) return true;
  const auto mask = static_cast<uint8_t>(0xffu << (8 - rest));
  return (a[full] & mask) == (b[full] & mask);
}

}  // namespace

std::optional<IpNetwork> parse_ip_network(std::string_view text) {
  if (text.empty() || text.size() > 64) return std::nullopt;
  const size_t slash = text.find('/');
  const std::string address(text.substr(0, slash));
  IpNetwork network;
  unsigned max_prefix = 128;
  in_addr v4{};
  in6_addr v6{};
  if (::inet_pton(AF_INET, address.c_str(), &v4) == 1) {
    network.address = mapped_v4(v4);
    max_prefix = 32;
  } else if (::inet_pton(AF_INET6, address.c_str(), &v6) == 1) {
    std::memcpy(network.address.data(), v6.s6_addr, 16);
  } else {
    return std::nullopt;
  }
  unsigned prefix = max_prefix;
  if (slash != std::string_view::npos) {
    const std::string_view digits = text.substr(slash + 1);
    if (digits.empty() || digits.size() > 3) return std::nullopt;
    const auto [end, ec] =
        std::from_chars(digits.data(), digits.data() + digits.size(), prefix);
    if (ec != std::errc{} || end != digits.data() + digits.size() ||
        prefix > max_prefix) {
      return std::nullopt;
    }
  }
  network.prefix = static_cast<uint8_t>(max_prefix == 32 ? prefix + 96 : prefix);
  return network;
}

bool source_allowed(const std::vector<IpNetwork>& allow,
                    evhttp_request* request) {
  if (allow.empty()) return true;
  if (request == nullptr) return false;
  evhttp_connection* connection = evhttp_request_get_connection(request);
  if (connection == nullptr) return false;
  const sockaddr* address = evhttp_connection_get_addr(connection);
  if (address == nullptr) return false;
  std::array<uint8_t, 16> peer{};
  if (address->sa_family == AF_INET) {
    peer = mapped_v4(reinterpret_cast<const sockaddr_in*>(address)->sin_addr);
  } else if (address->sa_family == AF_INET6) {
    std::memcpy(peer.data(),
                reinterpret_cast<const sockaddr_in6*>(address)->sin6_addr.s6_addr,
                16);
  } else {
    return false;
  }
  for (const auto& network : allow) {
    if (prefix_matches(peer, network.address, network.prefix)) return true;
  }
  return false;
}

}  // namespace mtdd::control::detail
