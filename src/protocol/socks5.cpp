// SOCKS5 CONNECT client handshake (RFC 1928, RFC 1929). Pure: the runtime
// moves the bytes; see Socks5Client in mtdd/protocol.hpp.
#include "mtdd/protocol.hpp"

#include <algorithm>
#include <array>
#include <string>
#include <utility>

namespace mtdd::protocol {
namespace {

constexpr std::uint8_t kVersion = 5;
constexpr std::uint8_t kMethodNone = 0x00;
constexpr std::uint8_t kMethodPassword = 0x02;
constexpr std::uint8_t kAuthVersion = 1;
constexpr std::uint8_t kCommandConnect = 1;
constexpr std::uint8_t kAtypV4 = 1;
constexpr std::uint8_t kAtypDomain = 3;
constexpr std::uint8_t kAtypV6 = 4;

const char* reply_text(std::uint8_t code) {
  switch (code) {
    case 1: return "general failure";
    case 2: return "connection not allowed by ruleset";
    case 3: return "network unreachable";
    case 4: return "host unreachable";
    case 5: return "connection refused";
    case 6: return "TTL expired";
    case 7: return "command not supported";
    case 8: return "address type not supported";
    default: return "unknown reply";
  }
}

void put_port(Bytes& out, std::uint16_t port) {
  out.push_back(static_cast<std::uint8_t>(port >> 8));
  out.push_back(static_cast<std::uint8_t>(port));
}

std::uint16_t port_at(const Bytes& bytes, std::size_t pos) {
  return static_cast<std::uint16_t>((static_cast<unsigned>(bytes[pos]) << 8U) | bytes[pos + 1]);
}

}  // namespace

Socks5Client::Socks5Client(Endpoint target, std::string username, std::string password)
    : target_(target), username_(std::move(username)), password_(std::move(password)) {
  if (username_.size() > 255 || password_.size() > 255) {
    throw std::invalid_argument("SOCKS5 username and password are at most 255 bytes");
  }
  if (username_.empty() != password_.empty()) {
    throw std::invalid_argument("SOCKS5 username and password are set together");
  }
  if (target_.port == 0) throw std::invalid_argument("SOCKS5 target port must be non-zero");
}

Bytes Socks5Client::start() {
  started_ = true;
  const bool auth = !username_.empty();
  return Bytes{kVersion, 1, auth ? kMethodPassword : kMethodNone};
}

std::size_t Socks5Client::want() const noexcept {
  if (status_ != Status::NeedMore || !started_) return 0;
  return need_ - have_.size();
}

Socks5Client::Status Socks5Client::fail(std::string message) {
  status_ = Status::Failed;
  stage_ = Stage::Finished;
  error_ = std::move(message);
  have_.clear();
  return status_;
}

Socks5Client::Status Socks5Client::feed(std::span<const std::uint8_t> in, Bytes& out) {
  if (status_ != Status::NeedMore) return status_;
  if (!started_) return fail("SOCKS5 data before the greeting");
  while (!in.empty() && status_ == Status::NeedMore) {
    const std::size_t take = std::min(in.size(), need_ - have_.size());
    have_.insert(have_.end(), in.begin(), in.begin() + static_cast<std::ptrdiff_t>(take));
    in = in.subspan(take);
    if (have_.size() == need_) advance(out);
  }
  if (!in.empty() && status_ != Status::Failed) {
    // More than want(): the caller read past the handshake.
    return fail("SOCKS5 reply longer than expected");
  }
  return status_;
}

void Socks5Client::advance(Bytes& out) {
  switch (stage_) {
    case Stage::Method: {
      const std::uint8_t offered = username_.empty() ? kMethodNone : kMethodPassword;
      if (have_[0] != kVersion) {
        fail("not a SOCKS5 server");
        return;
      }
      if (have_[1] != offered) {
        fail(have_[1] == 0xFF ? "SOCKS5 server accepts none of the offered methods"
                              : "SOCKS5 server chose a method that was not offered");
        return;
      }
      have_.clear();
      if (offered == kMethodPassword) {
        out.push_back(kAuthVersion);
        out.push_back(static_cast<std::uint8_t>(username_.size()));
        out.insert(out.end(), username_.begin(), username_.end());
        out.push_back(static_cast<std::uint8_t>(password_.size()));
        out.insert(out.end(), password_.begin(), password_.end());
        stage_ = Stage::Auth;
        need_ = 2;
        return;
      }
      [[fallthrough]];
    }
    case Stage::Auth: {
      if (stage_ == Stage::Auth) {
        if (have_[1] != 0) {
          fail("SOCKS5 authentication failed");
          return;
        }
        have_.clear();
      }
      out.push_back(kVersion);
      out.push_back(kCommandConnect);
      out.push_back(0);
      if (target_.ipv6) {
        out.push_back(kAtypV6);
        out.insert(out.end(), target_.address.begin(), target_.address.end());
      } else {
        out.push_back(kAtypV4);
        out.insert(out.end(), target_.address.begin(), target_.address.begin() + 4);
      }
      put_port(out, target_.port);
      stage_ = Stage::Head;
      need_ = 4;
      return;
    }
    case Stage::Head: {
      if (have_[0] != kVersion) {
        fail("not a SOCKS5 reply");
        return;
      }
      if (have_[1] != 0) {
        fail(std::string("SOCKS5 connect failed: ") + reply_text(have_[1]));
        return;
      }
      address_type_ = have_[3];
      have_.clear();
      stage_ = Stage::Address;
      switch (address_type_) {
        case kAtypV4: need_ = 4 + 2; return;
        case kAtypV6: need_ = 16 + 2; return;
        case kAtypDomain: need_ = 1; return;
        default: fail("SOCKS5 reply with an unknown address type"); return;
      }
    }
    case Stage::Address: {
      if (address_type_ == kAtypDomain && need_ == 1) {
        if (have_[0] == 0) {
          fail("SOCKS5 reply with an empty domain");
          return;
        }
        need_ = 1 + have_[0] + 2;  // keep the length byte in have_
        return;
      }
      if (address_type_ == kAtypV4) {
        bound_ = Endpoint::v4({have_[0], have_[1], have_[2], have_[3]}, port_at(have_, 4));
      } else if (address_type_ == kAtypV6) {
        std::array<std::uint8_t, 16> address{};
        std::copy_n(have_.begin(), address.size(), address.begin());
        bound_ = Endpoint::v6(address, port_at(have_, 16));
      }
      have_.clear();
      stage_ = Stage::Finished;
      status_ = Status::Done;
      need_ = 0;
      return;
    }
    case Stage::Finished:
      return;
  }
}

}  // namespace mtdd::protocol
