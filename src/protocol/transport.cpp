#include "mtdd/protocol.hpp"

#include <algorithm>
#include <cstring>
#include <stdexcept>

namespace mtdd::protocol {
namespace {

std::uint32_t rd32(std::span<const std::uint8_t> b, std::size_t off = 0) {
  return static_cast<std::uint32_t>(b[off]) |
         (static_cast<std::uint32_t>(b[off + 1]) << 8) |
         (static_cast<std::uint32_t>(b[off + 2]) << 16) |
         (static_cast<std::uint32_t>(b[off + 3]) << 24);
}
void put32(Bytes& out, std::uint32_t v) {
  out.push_back(static_cast<std::uint8_t>(v));
  out.push_back(static_cast<std::uint8_t>(v >> 8));
  out.push_back(static_cast<std::uint8_t>(v >> 16));
  out.push_back(static_cast<std::uint8_t>(v >> 24));
}

struct FrameHeader {
  std::size_t len{0};  // bytes declared after the header
  bool quick_ack{false};
};

enum class HeaderScan { Ok, NeedMore, Invalid };

// Header-time validation, matching the baseline exactly: the declared length is
// checked (zero / above the limit) as soon as the 4-byte word is available.
// Alignment and padding depend on the complete payload, so they are checked by
// payload_keep() only after 4 + len bytes are present.
HeaderScan scan_header(std::span<const std::uint8_t> src, std::size_t pos,
                       std::size_t max_message, FrameHeader& out) {
  if (src.size() - pos < 4) return HeaderScan::NeedMore;
  const std::uint32_t word = rd32(src, pos);
  const std::size_t len = word & 0x7fffffffu;
  if (len == 0 || len > max_message) return HeaderScan::Invalid;
  out = FrameHeader{len, (word & 0x80000000u) != 0};
  return HeaderScan::Ok;
}

// Payload-time validation: returns the number of payload bytes the Message keeps
// and false for an Intermediate length that is not 4-byte aligned or a Secure
// frame that is all padding. The baseline performed these checks only after the
// declared payload was complete.
bool payload_keep(ProtoTag tag, std::size_t len, std::size_t& keep) {
  keep = len;
  if (tag == ProtoTag::Secure) {
    keep -= len % 4;  // padded intermediate: receiver truncates padding
    return keep != 0;
  }
  return len % 4 == 0;
}

// Decodes contiguous complete frames from `src` into `out`. Every payload is
// copied exactly once, straight from `src` into its owned Message; no output
// aliases the input. On success `consumed` is the size of the decoded prefix
// (an incomplete tail starts there). On a protocol error the return value is
// false and `consumed` is unused: the caller keeps the bytes observable exactly
// as the baseline did.
bool decode_frames(std::span<const std::uint8_t> src, ProtoTag tag, std::size_t max_message,
                   std::size_t& consumed, std::vector<TransportDecoder::Message>& out) {
  std::size_t pos = 0;
  for (;;) {
    FrameHeader frame;
    const HeaderScan scan = scan_header(src, pos, max_message, frame);
    if (scan == HeaderScan::Invalid) return false;
    if (scan == HeaderScan::NeedMore) break;
    if (src.size() - pos - 4 < frame.len) break;  // incomplete payload

    std::size_t keep = 0;
    if (!payload_keep(tag, frame.len, keep)) return false;

    TransportDecoder::Message msg;
    const auto begin = src.begin() + static_cast<std::ptrdiff_t>(pos + 4);
    msg.data.assign(begin, begin + static_cast<std::ptrdiff_t>(keep));
    msg.quick_ack = frame.quick_ack;
    out.push_back(std::move(msg));
    pos += 4 + frame.len;
  }
  consumed = pos;
  return true;
}

}  // namespace

TransportDecoder::TransportDecoder(Config config)
    : tag_(config.tag), max_message_(config.max_message) {
  if (tag_ == ProtoTag::Abridged) {
    throw std::invalid_argument("abridged transport is not supported");
  }
  if (max_message_ == 0) throw std::invalid_argument("max_message must be non-zero");
}

Status TransportDecoder::feed(std::span<const std::uint8_t> wire, std::vector<Message>& out) {
  if (buffer_.empty()) {
    // Fast path: the accumulation buffer is empty, so complete frames are parsed
    // directly from the caller's span and each payload is copied once into its
    // Message. Only an incomplete tail is copied into buffer_.
    std::size_t consumed = 0;
    if (!decode_frames(wire, tag_, max_message_, consumed, out)) {
      // Preserve the baseline observation that a failing frame leaves the
      // unparsed input visible through buffered(); the decoder is terminal after
      // a protocol error and is discarded together with its retained bytes.
      buffer_.assign(wire.begin(), wire.end());
      return Status::ProtocolError;
    }
    if (consumed < wire.size()) {
      buffer_.assign(wire.begin() + static_cast<std::ptrdiff_t>(consumed), wire.end());
    }
    return out.empty() ? Status::NeedMoreData : Status::Ok;
  }

  // Fragmented path: the original 75713d0 sequence, kept explicit on purpose.
  // Append the new bytes, parse in place, then erase the consumed prefix. This
  // is deliberately not routed through decode_frames(): a partially buffered
  // stream must have exactly the baseline shape and cost, and the two paths
  // must not share logic that can drift. The equivalence tests run every case
  // through both branches.
  buffer_.insert(buffer_.end(), wire.begin(), wire.end());
  std::size_t pos = 0;
  while (buffer_.size() - pos >= 4) {
    const std::uint32_t word = rd32(buffer_, pos);
    const bool quick_ack = (word & 0x80000000u) != 0;
    const std::size_t len = word & 0x7fffffffu;
    if (len == 0 || len > max_message_) return Status::ProtocolError;
    if (buffer_.size() - pos < 4 + len) break;

    const auto data = std::span<const std::uint8_t>(buffer_).subspan(pos + 4, len);
    std::size_t keep = len;
    if (tag_ == ProtoTag::Secure) {
      keep -= len % 4;  // padded intermediate: receiver truncates padding
      if (keep == 0) return Status::ProtocolError;
    } else if (len % 4 != 0) {
      return Status::ProtocolError;
    }

    Message msg;
    msg.data.assign(data.begin(), data.begin() + static_cast<std::ptrdiff_t>(keep));
    msg.quick_ack = quick_ack;
    out.push_back(std::move(msg));
    pos += 4 + len;
  }
  if (pos) buffer_.erase(buffer_.begin(), buffer_.begin() + static_cast<std::ptrdiff_t>(pos));
  if (buffer_.empty() && buffer_.capacity() > 64u * 1024u) Bytes().swap(buffer_);
  return out.empty() ? Status::NeedMoreData : Status::Ok;
}

std::size_t TransportDecoder::buffered() const { return buffer_.size(); }
std::size_t TransportDecoder::retained_bytes() const { return buffer_.capacity(); }

void TransportDecoder::release_idle() {
    if (buffer_.empty()) {
        buffer_.clear();
        if (buffer_.capacity() != 0) Bytes().swap(buffer_);
    }
}

void encode_transport_message(ProtoTag tag, std::span<const std::uint8_t> data,
                              std::vector<std::uint8_t>& out, const RandomFn* random) {
  if (tag == ProtoTag::Abridged) throw std::invalid_argument("abridged transport is not supported");
  if (data.empty() || data.size() % 4 != 0) {
    throw std::invalid_argument("transport payload must be non-empty and 4-byte aligned");
  }
  std::size_t padding = 0;
  std::array<std::uint8_t, kSecureMaxPadding> pad{};
  if (tag == ProtoTag::Secure) {
    if (random && *random) {
      std::uint8_t r = 0;
      (*random)(std::span<std::uint8_t>(&r, 1));
      padding = r % (secure_padding_limit(data.size(), kSecureMaxPadding) + 1);
      if (padding) (*random)(std::span<std::uint8_t>(pad).first(padding));
    }
  }
  put32(out, static_cast<std::uint32_t>(data.size() + padding));
  out.insert(out.end(), data.begin(), data.end());
  out.insert(out.end(), pad.begin(), pad.begin() + static_cast<std::ptrdiff_t>(padding));
}

void encode_quick_ack(ProtoTag tag, std::array<std::uint8_t, 4> confirm,
                      std::vector<std::uint8_t>& out) {
  if (tag == ProtoTag::Abridged) {
    out.insert(out.end(), {confirm[3], confirm[2], confirm[1], confirm[0]});
  } else {
    out.insert(out.end(), confirm.begin(), confirm.end());
  }
}

}  // namespace mtdd::protocol
