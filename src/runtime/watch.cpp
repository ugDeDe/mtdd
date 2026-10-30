// Config::watch_ips: a per-stage journal log for connections from listed
// addresses, to study scanners and probes. Every hook is behind
// `client.watched`, so other connections pay one branch.
//
//   mtdd watch: conn=17 peer=1.2.3.4:5555 +0ms accept syn=ttl:55,win:64240,...
//   mtdd watch: conn=17 peer=1.2.3.4:5555 +80ms hello len=1785 sni=... tls=chrome
//   mtdd watch: conn=17 peer=1.2.3.4:5555 +81ms auth user=dd
//   mtdd watch: conn=17 peer=1.2.3.4:5555 +160ms tls_ready dc=2 route=me platform=Android
//   mtdd watch: conn=17 peer=1.2.3.4:5555 +240ms frame len=40 auth_key_id=0 msg=req_pq_multi
//   mtdd watch: conn=17 peer=1.2.3.4:5555 +9s close phase=relay reason=client_eof rx=... tx=...
#include "internal.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cctype>
#include <cstdio>
#include <cstring>
#include <string>

namespace mtdd {
namespace detail {

std::optional<WatchNet> parse_watch_net(std::string_view text) {
    const std::size_t slash = text.find('/');
    const std::string address(text.substr(0, slash));
    WatchNet net;
    int bits = -1;
    if (slash != std::string_view::npos) {
        const std::string digits(text.substr(slash + 1));
        if (digits.empty() || digits.size() > 3 ||
            digits.find_first_not_of("0123456789") != std::string::npos) {
            return std::nullopt;
        }
        bits = std::stoi(digits);
    }
    in_addr v4{};
    in6_addr v6{};
    if (::inet_pton(AF_INET, address.c_str(), &v4) == 1) {
        if (bits > 32) return std::nullopt;
        net.address[10] = 0xff;
        net.address[11] = 0xff;
        std::memcpy(net.address.data() + 12, &v4, 4);
        net.prefix = static_cast<std::uint8_t>(96 + (bits < 0 ? 32 : bits));
    } else if (::inet_pton(AF_INET6, address.c_str(), &v6) == 1) {
        if (bits > 128) return std::nullopt;
        std::memcpy(net.address.data(), &v6, 16);
        net.prefix = static_cast<std::uint8_t>(bits < 0 ? 128 : bits);
    } else {
        return std::nullopt;
    }
    return net;
}

bool watch_net_contains(const WatchNet& net, const protocol::Endpoint& peer) noexcept {
    std::array<std::uint8_t, 16> mapped{};
    if (peer.ipv6) {
        mapped = peer.address;
    } else {
        mapped[10] = 0xff;
        mapped[11] = 0xff;
        std::memcpy(mapped.data() + 12, peer.address.data(), 4);
    }
    const unsigned full = net.prefix / 8U;
    for (unsigned i = 0; i < full; ++i) {
        if (mapped[i] != net.address[i]) return false;
    }
    const unsigned rest = net.prefix % 8U;
    if (rest == 0) return true;
    const auto mask = static_cast<std::uint8_t>(0xffU << (8U - rest));
    return (mapped[full] & mask) == (net.address[full] & mask);
}

} // namespace detail

namespace {

std::string peer_text(const protocol::Endpoint& peer) {
    char text[INET6_ADDRSTRLEN] = {};
    ::inet_ntop(peer.ipv6 ? AF_INET6 : AF_INET, peer.address.data(), text, sizeof(text));
    return peer.ipv6 ? "[" + std::string(text) + "]:" + std::to_string(peer.port)
                     : std::string(text) + ":" + std::to_string(peer.port);
}

std::string hex(std::span<const std::uint8_t> bytes) {
    static constexpr char kDigits[] = "0123456789abcdef";
    std::string out;
    out.reserve(bytes.size() * 2);
    for (const auto byte : bytes) {
        out.push_back(kDigits[byte >> 4]);
        out.push_back(kDigits[byte & 15]);
    }
    return out;
}

// Printable view of the first bytes (HTTP/SSH banners and the like).
std::string printable(std::span<const std::uint8_t> bytes) {
    std::string out;
    for (const auto byte : bytes) {
        out.push_back(byte >= 0x20 && byte < 0x7f && byte != ' ' ? static_cast<char>(byte) : '.');
    }
    return out;
}

const char* layout_name(detail::SynLayout layout) {
    switch (layout) {
        case detail::SynLayout::linux_stack: return "linux";
        case detail::SynLayout::apple_stack: return "apple";
        case detail::SynLayout::windows_stack: return "windows";
        case detail::SynLayout::other: break;
    }
    return "other";
}

const char* tls_name(detail::TlsTemplate tls) {
    switch (tls) {
        case detail::TlsTemplate::safari: return "safari";
        case detail::TlsTemplate::chrome: return "chrome";
        case detail::TlsTemplate::other: break;
    }
    return "other";
}

const char* phase_name(std::uint8_t phase) {
    static constexpr const char* kNames[] = {"tls_hello", "tls_handshake", "relay", "fallback"};
    return phase < 4 ? kNames[phase] : "?";
}

const char* close_name(control::RelayCloseReason reason) {
    static constexpr const char* kNames[] = {
        "other",   "client_eof",   "client_error", "client_timeout", "idle_timeout",
        "me_lost", "backpressure", "remote_close", "revoked",        "shutdown",
        "device_limit"};
    const auto index = static_cast<std::size_t>(reason);
    return index < std::size(kNames) ? kNames[index] : "?";
}

// Unencrypted MTProto (auth_key_id 0): auth_key_id(8) msg_id(8) length(4)
// then the TL constructor of the key-exchange call.
const char* tl_name(std::uint32_t constructor) {
    switch (constructor) {
        case 0xbe7e8ef1U: return "req_pq_multi";
        case 0x60469778U: return "req_pq";
        case 0xd712e4beU: return "req_DH_params";
        case 0xf5045f1fU: return "set_client_DH_params";
        default: return nullptr;
    }
}

} // namespace

void Runtime::Impl::watch_log(const Client& client, std::string_view event,
                              std::string_view detail) {
    const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                             Clock::now() - client.watch_start)
                             .count();
    std::string line = "mtdd watch: conn=" + std::to_string(client.token) +
                       " peer=" + peer_text(client.peer) + " +" + std::to_string(elapsed) +
                       "ms " + std::string(event);
    if (!detail.empty()) {
        line.push_back(' ');
        line.append(detail);
    }
    line.push_back('\n');
    // One write() per line keeps lines from different reactors whole.
    (void)!::write(STDERR_FILENO, line.data(), line.size());
}

void Runtime::Impl::watch_accept(Client& client, Time now) {
    client.watch_start = now;
    const auto& syn = client.syn;
    char detail[160];
    if (syn.valid) {
        std::snprintf(detail, sizeof(detail),
                      "syn=ttl:%u,win:%u,mss:%u,ws:%d,ts:%d,layout:%s worker=%zu",
                      static_cast<unsigned>(syn.ttl), static_cast<unsigned>(syn.window),
                      static_cast<unsigned>(syn.mss), static_cast<int>(syn.wscale),
                      syn.timestamps ? 1 : 0, layout_name(syn.layout), worker_index_);
    } else {
        std::snprintf(detail, sizeof(detail), "syn=unavailable worker=%zu", worker_index_);
    }
    watch_log(client, "accept", detail);
}

void Runtime::Impl::watch_hello(const Client& client, std::span<const std::uint8_t> record) {
    const bool tls = record.size() >= 3 && record[0] == 0x16 && record[1] == 0x03;
    std::string detail = "bytes=" + std::to_string(record.size());
    if (!tls) {
        // Only the record header has been read so far: peek at what follows
        // (the socket keeps it) to show the probe's request line or banner.
        std::array<std::uint8_t, 64> more{};
        std::size_t have = 0;
        const std::size_t keep = std::min(record.size(), more.size());
        std::memcpy(more.data(), record.data(), keep);
        have = keep;
        if (client.fd.valid() && have < more.size()) {
            const ssize_t peeked = ::recv(client.fd.get(), more.data() + have, more.size() - have,
                                          MSG_PEEK | MSG_DONTWAIT);
            if (peeked > 0) have += static_cast<std::size_t>(peeked);
        }
        const auto shown = std::span<const std::uint8_t>(more.data(), have);
        detail += " not_tls hex=" + hex(shown.first(std::min<std::size_t>(have, 24))) +
                  " text=" + printable(shown);
        watch_log(client, "first_bytes", detail);
        return;
    }
    const auto sni = protocol::client_hello_sni(record);
    detail += std::string(" sni=") + (sni ? *sni : "-") +
              " tls=" + tls_name(detail::classify_client_hello(record));
    watch_log(client, "hello", detail);
}

void Runtime::Impl::watch_frame(Client& client, std::span<const std::uint8_t> payload,
                                std::size_t length) {
    if (client.watch_frames >= 12) return;
    ++client.watch_frames;
    std::string detail = "len=" + std::to_string(length);
    if (payload.size() >= 8) {
        std::uint64_t key = 0;
        for (int i = 7; i >= 0; --i) key = (key << 8) | payload[static_cast<std::size_t>(i)];
        char text[24];
        std::snprintf(text, sizeof(text), "%016llx", static_cast<unsigned long long>(key));
        detail += std::string(" auth_key_id=") + text;
        if (key == 0 && payload.size() >= 24) {
            std::uint32_t constructor = 0;
            for (int i = 23; i >= 20; --i) {
                constructor = (constructor << 8) | payload[static_cast<std::size_t>(i)];
            }
            const char* name = tl_name(constructor);
            char ctor[16];
            std::snprintf(ctor, sizeof(ctor), "%08x", constructor);
            detail += std::string(" msg=") + (name ? name : ctor);
        }
    }
    watch_log(client, "frame", detail);
}

void Runtime::Impl::watch_close(const Client& client) {
    std::string detail = std::string("phase=") +
                         phase_name(static_cast<std::uint8_t>(client.phase)) +
                         " reason=" + close_name(client.close_reason) +
                         " eof=" + (client.read_eof ? "1" : "0");
    if (!client.user_name.empty()) detail += " user=" + client.user_name;
    tcp_info info{};
    socklen_t length = sizeof(info);
    if (client.fd.valid() &&
        ::getsockopt(client.fd.get(), IPPROTO_TCP, TCP_INFO, &info, &length) == 0) {
        detail += " rx=" + std::to_string(info.tcpi_bytes_received) +
                  " tx=" + std::to_string(info.tcpi_bytes_acked) +
                  " rtt_ms=" + std::to_string(info.tcpi_rtt / 1000U);
    }
    watch_log(client, "close", detail);
}

} // namespace mtdd
