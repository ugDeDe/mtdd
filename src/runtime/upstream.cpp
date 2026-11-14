// Outbound upstreams (Config::upstreams): which way an outbound connection
// leaves the host. Telegram connections (ME, Direct) use the default scope,
// masking uses Config::masking_scope. A "direct" upstream connects from here,
// optionally bound to an interface or source address; a "socks5" upstream
// connects to the proxy and runs a non-blocking SOCKS5 handshake on the
// reactor before the connection is used.
#include "internal.hpp"
#include "random.hpp"

#include <sys/socket.h>

#include <algorithm>
#include <array>
#include <cerrno>

namespace mtdd {

const UpstreamConfig* Runtime::Impl::pick_upstream(std::string_view scope) {
    const auto& upstreams = config_.upstreams;
    if (upstreams.empty()) return nullptr;
    const auto matches = [&](const UpstreamConfig& upstream) {
        if (scope.empty()) return upstream.scopes.empty();
        return std::find(upstream.scopes.begin(), upstream.scopes.end(), scope) != upstream.scopes.end();
    };
    std::uint64_t total = 0;
    for (const auto& upstream : upstreams) {
        if (matches(upstream)) total += upstream.weight;
    }
    if (total == 0) return nullptr;
    std::uint64_t ticket = detail::random_u32(random_) % total;
    for (const auto& upstream : upstreams) {
        if (!matches(upstream)) continue;
        if (ticket < upstream.weight) return &upstream;
        ticket -= upstream.weight;
    }
    return nullptr;
}

Runtime::Impl::Dialed Runtime::Impl::dial(std::string_view scope, const std::string& host,
                                          std::uint16_t port) {
    Dialed result;
    result.upstream = pick_upstream(scope);
    if (result.upstream == nullptr) {
        result.connected = io::connect_tcp(host, port);
        return result;
    }
    const UpstreamConfig& upstream = *result.upstream;
    io::ConnectOptions options;
    options.device = upstream.interface;
    options.bind_address = upstream.bind_address;
    if (upstream.type == UpstreamConfig::Type::direct) {
        result.connected = io::connect_tcp(host, port, options);
        return result;
    }
    const auto target = to_protocol_endpoint(io::Endpoint{host, port});
    if (!target || target->port == 0) {
        result.connected.error = EINVAL;
        return result;
    }
    try {
        result.socks = std::make_unique<protocol::Socks5Client>(*target, upstream.username,
                                                                upstream.password);
    } catch (const std::exception&) {
        result.connected.error = EINVAL;
        return result;
    }
    result.connected = io::connect_tcp(upstream.host, upstream.port, options);
    if (!result.connected.ok()) result.socks.reset();
    return result;
}

namespace {

// The handshake messages are a few hundred bytes at most and go to a freshly
// connected socket: a short write means the connection is unusable.
bool send_handshake(int fd, const protocol::Bytes& bytes) {
    std::size_t sent = 0;
    while (sent < bytes.size()) {
        const ssize_t n = ::send(fd, bytes.data() + sent, bytes.size() - sent,
                                 MSG_NOSIGNAL | MSG_DONTWAIT);
        if (n > 0) {
            sent += static_cast<std::size_t>(n);
        } else if (n < 0 && errno == EINTR) {
            continue;
        } else {
            return false;
        }
    }
    return true;
}

} // namespace

Runtime::Impl::SocksProgress Runtime::Impl::socks_start(int fd, protocol::Socks5Client& socks) {
    if (socks.started()) return SocksProgress::pending;
    return send_handshake(fd, socks.start()) ? SocksProgress::pending : SocksProgress::failed;
}

Runtime::Impl::SocksProgress Runtime::Impl::socks_read(int fd, protocol::Socks5Client& socks) {
    std::array<std::uint8_t, 512> buffer{};
    protocol::Bytes reply;
    while (socks.status() == protocol::Socks5Client::Status::NeedMore) {
        const std::size_t want = std::min(socks.want(), buffer.size());
        if (want == 0) return SocksProgress::failed;
        const ssize_t n = ::recv(fd, buffer.data(), want, MSG_DONTWAIT);
        if (n > 0) {
            reply.clear();
            socks.feed(std::span<const std::uint8_t>(buffer.data(), static_cast<std::size_t>(n)), reply);
            if (!reply.empty() && !send_handshake(fd, reply)) return SocksProgress::failed;
        } else if (n == 0) {
            return SocksProgress::failed;
        } else if (errno == EINTR) {
            continue;
        } else if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return SocksProgress::pending;
        } else {
            return SocksProgress::failed;
        }
    }
    return socks.status() == protocol::Socks5Client::Status::Done ? SocksProgress::done
                                                                  : SocksProgress::failed;
}

} // namespace mtdd
