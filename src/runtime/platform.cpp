// Coarse client platform from the TCP SYN and the FakeTLS ClientHello template.
// Reference fingerprints (captured from official clients):
//
//   Apple   ClientHello: Safari template, fixed extension order
//             0-23-65281-10-11-16-5-13-18-51-45-43-27 (iOS, macOS, and
//             unofficial clients built on Telegram-iOS look the same)
//           SYN: mss,nop,ws6,nop,nop,ts,sackOK,eol, window 65535, TTL 64
//   Windows ClientHello: Chrome template (shuffled extensions, ALPS, ECH)
//           SYN: mss,nop,ws8,nop,nop,sackOK, TTL 128; with timestamps
//           enabled mss,nop,ws8,sackOK,ts.
//
// TTL is not checked: it is commonly rewritten (to 64 or 128) to hide
// tethering from mobile carriers. The option layout and window are kept.
//   Linux   ClientHello: Chrome template
//           SYN: mss,sackOK,ts,nop,ws7, window 64240 (44 x MSS), TTL 64
//   Android ClientHello: Chrome template
//           SYN: mss,sackOK,ts,nop,ws9, window 65535, TTL 64
//
// Option layouts are compared without NOPs: middleboxes add and remove them,
// and some replace the timestamps option with NOPs (Linux mss,sackOK,ws).
// Anything else is undefined. Middleboxes that terminate TCP (proxy VPNs)
// replace the SYN; the result is then undefined or the middlebox's OS.
#include "internal.hpp"

#include <algorithm>
#include <array>

namespace mtdd::detail {
namespace {

// Option kinds in order, NOPs removed: 2 mss, 3 wscale, 4 sackOK, 8 timestamps.
constexpr std::array<std::uint8_t, 4> kLinuxLayout{2, 4, 8, 3};
constexpr std::array<std::uint8_t, 3> kLinuxNoTsLayout{2, 4, 3};
constexpr std::array<std::uint8_t, 4> kAppleLayout{2, 3, 8, 4};
constexpr std::array<std::uint8_t, 3> kWindowsLayout{2, 3, 4};
constexpr std::array<std::uint8_t, 4> kWindowsTsLayout{2, 3, 4, 8};
constexpr std::array<std::uint16_t, 10> kSafariOrder{0, 23, 65281, 10, 11, 16, 5, 13, 18, 51};

bool grease(std::uint16_t value) noexcept {
    return (value & 0x0f0fU) == 0x0a0aU && (value >> 8) == (value & 0xffU);
}

std::uint16_t be16(std::span<const std::uint8_t> data, std::size_t at) noexcept {
    return static_cast<std::uint16_t>((data[at] << 8) | data[at + 1]);
}

template <std::size_t N>
bool layout_is(const std::array<std::uint8_t, 8>& kinds, std::uint8_t count,
               const std::array<std::uint8_t, N>& expected) noexcept {
    return count == N && std::equal(expected.begin(), expected.end(), kinds.begin());
}

} // namespace

const char* platform_name(Platform platform) noexcept {
    switch (platform) {
        case Platform::apple: return "Apple";
        case Platform::android: return "Android";
        case Platform::linux_desktop: return "Linux";
        case Platform::windows: return "Windows";
        case Platform::undefined: break;
    }
    return "Undefined";
}

SynPrint parse_saved_syn(std::span<const std::uint8_t> syn) noexcept {
    SynPrint print;
    std::size_t tcp = 0;
    if (syn.size() >= 20 && (syn[0] >> 4) == 4) {
        tcp = static_cast<std::size_t>(syn[0] & 0x0f) * 4;
        print.ttl = syn[8];
    } else if (syn.size() >= 40 && (syn[0] >> 4) == 6) {
        tcp = 40;  // extension headers are not expected on a SYN
        print.ttl = syn[7];
    } else {
        return print;
    }
    if (tcp < 20 || syn.size() < tcp + 20) return print;
    const std::size_t end = std::min(syn.size(), tcp + static_cast<std::size_t>(syn[tcp + 12] >> 4) * 4);
    print.window = be16(syn, tcp + 14);
    std::array<std::uint8_t, 8> kinds{};
    std::uint8_t count = 0;
    for (std::size_t at = tcp + 20; at < end;) {
        const std::uint8_t kind = syn[at];
        if (kind == 0) break;  // EOL ends the list
        if (kind == 1) {
            ++at;
            continue;
        }
        if (count < kinds.size()) kinds[count] = kind;
        ++count;
        if (at + 1 >= end || syn[at + 1] < 2 || at + syn[at + 1] > end) break;
        const std::uint8_t length = syn[at + 1];
        if (kind == 2 && length == 4) print.mss = be16(syn, at + 2);
        if (kind == 3 && length == 3) print.wscale = static_cast<std::int8_t>(syn[at + 2]);
        if (kind == 8) print.timestamps = true;
        at += length;
    }
    if (layout_is(kinds, count, kLinuxLayout) || layout_is(kinds, count, kLinuxNoTsLayout)) {
        print.layout = SynLayout::linux_stack;
    } else if (layout_is(kinds, count, kAppleLayout)) {
        print.layout = SynLayout::apple_stack;
    } else if (layout_is(kinds, count, kWindowsLayout) ||
               layout_is(kinds, count, kWindowsTsLayout)) {
        print.layout = SynLayout::windows_stack;
    }
    print.valid = true;
    return print;
}

TlsTemplate classify_client_hello(std::span<const std::uint8_t> record) noexcept {
    // TLS record header (5) + handshake header (4) + version (2) + random (32).
    std::size_t at = 5 + 4 + 2 + 32;
    if (record.size() < at + 1 || record[5] != 0x01) return TlsTemplate::other;
    at += 1 + record[at];  // session id
    if (record.size() < at + 2) return TlsTemplate::other;
    at += 2 + be16(record, at);  // cipher suites
    if (record.size() < at + 1) return TlsTemplate::other;
    at += 1 + record[at];  // compression methods
    if (record.size() < at + 2) return TlsTemplate::other;
    const std::size_t end = std::min(record.size(), at + 2 + be16(record, at));
    at += 2;
    std::array<std::uint16_t, kSafariOrder.size()> order{};
    std::size_t listed = 0;
    bool chrome_only = false;
    while (at + 4 <= end) {
        const std::uint16_t type = be16(record, at);
        at += 4 + be16(record, at + 2);
        if (grease(type)) continue;
        // ALPS (old and new codepoints) and ECH GREASE: Chrome, never Safari.
        if (type == 17513 || type == 17613 || type == 65037) chrome_only = true;
        if (listed < order.size()) order[listed] = type;
        ++listed;
    }
    if (chrome_only) return TlsTemplate::chrome;
    if (listed >= order.size() && order == kSafariOrder) return TlsTemplate::safari;
    return TlsTemplate::other;
}

Platform classify_platform(const SynPrint& syn, TlsTemplate tls) noexcept {
    if (tls == TlsTemplate::safari) return Platform::apple;
    if (tls != TlsTemplate::chrome || !syn.valid) return Platform::undefined;
    switch (syn.layout) {
        case SynLayout::apple_stack:
            return Platform::apple;  // Telegram Desktop on macOS
        case SynLayout::windows_stack:
            return Platform::windows;
        case SynLayout::linux_stack:
            if (syn.window == 65535 || syn.wscale >= 8) return Platform::android;
            if (syn.wscale >= 0 && syn.wscale <= 7) return Platform::linux_desktop;
            return Platform::undefined;
        case SynLayout::other:
            break;
    }
    return Platform::undefined;
}

} // namespace mtdd::detail
