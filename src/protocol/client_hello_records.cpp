// Reassembly of a FakeTLS ClientHello split over several TLS handshake records.
// Pure functions of the received bytes: no sockets, no runtime state.
#include "mtdd/protocol.hpp"

#include <algorithm>
#include <array>

namespace mtdd::protocol {
namespace {

constexpr std::size_t kHeader = 5;
// Smallest canonical record body (reference min_tls_client_hello_size); the
// same bound validate_client_hello() applies to the single-record form.
constexpr std::size_t kMinClientHello = 100;

bool handshake_type(std::uint8_t type) { return type == 0x16; }
bool tls_major(std::uint8_t major) { return major == 0x03; }
bool tls_minor(std::uint8_t minor) { return minor == 0x01 || minor == 0x03; }

std::size_t record_length(std::span<const std::uint8_t> wire, std::size_t pos) {
  return (static_cast<std::size_t>(wire[pos + 3]) << 8) | wire[pos + 4];
}

ClientHelloScan verdict(HelloStatus status, std::size_t records, std::size_t want = 0) {
  ClientHelloScan out;
  out.status = status;
  out.want = want;
  out.records = records;
  return out;
}

}  // namespace

ClientHelloScan scan_client_hello(std::span<const std::uint8_t> wire) {
  std::size_t pos = 0;
  std::size_t records = 0;
  std::size_t received = 0;  // handshake bytes received so far
  std::size_t declared = 0;  // handshake bytes the seen record headers announce
  std::size_t need = 0;      // 4 + handshake length, once its 4 bytes are in
  std::array<std::uint8_t, 4> head{};

  while (true) {
    const std::size_t have = wire.size() - pos;
    if (have < kHeader) {
      // The first header is classified only once complete (as before); a
      // later one as soon as its type/version bytes contradict a fragment.
      if (records != 0 && ((have >= 1 && !handshake_type(wire[pos])) ||
                           (have >= 2 && !tls_major(wire[pos + 1])) ||
                           (have >= 3 && !tls_minor(wire[pos + 2])))) {
        return verdict(HelloStatus::Invalid, records);
      }
      return verdict(HelloStatus::NeedMoreData, records, kHeader - have);
    }
    if (!handshake_type(wire[pos]) || !tls_major(wire[pos + 1]) || !tls_minor(wire[pos + 2])) {
      return verdict(records == 0 ? HelloStatus::NotTls : HelloStatus::Invalid, records);
    }
    const std::size_t length = record_length(wire, pos);
    ++records;
    declared += length;
    // Bounded before any body byte is read: an empty fragment, a total over
    // the ClientHello limit, or more than the handshake message still needs.
    if (length == 0 || declared > kFakeTlsMaxClientHello || (need != 0 && declared > need)) {
      return verdict(HelloStatus::Invalid, records);
    }
    pos += kHeader;

    const std::size_t take = std::min(length, wire.size() - pos);
    for (std::size_t i = 0; i < take && received + i < head.size(); ++i) {
      head[received + i] = wire[pos + i];
    }
    received += take;
    pos += take;
    if (need == 0) {
      // Handshake type and length, decided byte by byte even when they are
      // themselves split across records.
      if (received >= 1 && head[0] != 0x01) return verdict(HelloStatus::Invalid, records);
      if (received >= 2) {
        // Smallest length the bytes received so far still allow.
        std::size_t floor = static_cast<std::size_t>(head[1]) << 16;
        if (received >= 3) floor |= static_cast<std::size_t>(head[2]) << 8;
        if (4 + floor > kFakeTlsMaxClientHello) return verdict(HelloStatus::Invalid, records);
      }
      if (received >= 4) {
        need = 4 + ((static_cast<std::size_t>(head[1]) << 16) |
                    (static_cast<std::size_t>(head[2]) << 8) | head[3]);
        if (need < kMinClientHello || need > kFakeTlsMaxClientHello || declared > need) {
          return verdict(HelloStatus::Invalid, records);
        }
      }
    }
    if (take < length) return verdict(HelloStatus::NeedMoreData, records, length - take);

    // Record complete.
    if (need != 0 && received == need) {
      return verdict(pos == wire.size() ? HelloStatus::Ok : HelloStatus::Invalid, records);
    }
    if (records == kFakeTlsMaxHelloRecords) return verdict(HelloStatus::Invalid, records);
  }
}

Bytes reassemble_client_hello(std::span<const std::uint8_t> wire) {
  Bytes out;
  std::size_t pos = 0;
  std::size_t records = 0;
  while (wire.size() - pos >= kHeader && records < kFakeTlsMaxHelloRecords) {
    if (!handshake_type(wire[pos]) || !tls_major(wire[pos + 1]) || !tls_minor(wire[pos + 2])) {
      break;
    }
    if (out.empty()) out.assign(wire.begin(), wire.begin() + static_cast<std::ptrdiff_t>(kHeader));
    const std::size_t length = record_length(wire, pos);
    const std::size_t room = kHeader + kFakeTlsMaxClientHello - out.size();
    const std::size_t take = std::min({length, wire.size() - pos - kHeader, room});
    const auto body = wire.subspan(pos + kHeader, take);
    out.insert(out.end(), body.begin(), body.end());
    ++records;
    if (take < length) break;
    pos += kHeader + length;
  }
  if (!out.empty()) {
    const std::size_t total = out.size() - kHeader;
    out[3] = static_cast<std::uint8_t>(total >> 8);
    out[4] = static_cast<std::uint8_t>(total);
  }
  return out;
}

}  // namespace mtdd::protocol
