#include "mtdd/io.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
#include <netinet/tcp.h>
#include <sys/socket.h>

#include <algorithm>
#include <cerrno>
#include <cstring>

namespace mtdd::io {

namespace {

/// Parses a numeric IPv4/IPv6 address (no hostnames, no brackets) and fills a
/// sockaddr with @p port. Returns false with errno-independent failure.
bool parse_endpoint(std::string_view address, std::uint16_t port,
                    sockaddr_storage& storage, socklen_t& length) noexcept {
    if (address.empty() || address.size() > static_cast<std::size_t>(INET6_ADDRSTRLEN)) {
        return false;
    }
    if (address.find('\0') != std::string_view::npos) {
        return false;
    }

    char text[INET6_ADDRSTRLEN + 1];
    std::memcpy(text, address.data(), address.size());
    text[address.size()] = '\0';

    sockaddr_in v4{};
    if (::inet_pton(AF_INET, text, &v4.sin_addr) == 1) {
        v4.sin_family = AF_INET;
        v4.sin_port = htons(port);
        std::memcpy(&storage, &v4, sizeof(v4));
        length = sizeof(v4);
        return true;
    }

    sockaddr_in6 v6{};
    if (::inet_pton(AF_INET6, text, &v6.sin6_addr) == 1) {
        v6.sin6_family = AF_INET6;
        v6.sin6_port = htons(port);
        std::memcpy(&storage, &v6, sizeof(v6));
        length = sizeof(v6);
        return true;
    }

    return false;
}

int open_tcp_socket(int family) noexcept {
    return ::socket(family, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
}

std::optional<Endpoint> endpoint_from(const sockaddr_storage& storage,
                                      socklen_t length) {
    if (storage.ss_family == AF_INET) {
        if (length < static_cast<socklen_t>(sizeof(sockaddr_in))) {
            return std::nullopt;
        }
        sockaddr_in address{};
        std::memcpy(&address, &storage, sizeof(address));
        char text[INET_ADDRSTRLEN]{};
        if (::inet_ntop(AF_INET, &address.sin_addr, text, sizeof(text)) == nullptr) {
            return std::nullopt;
        }
        return Endpoint{std::string(text), ntohs(address.sin_port)};
    }
    if (storage.ss_family == AF_INET6) {
        if (length < static_cast<socklen_t>(sizeof(sockaddr_in6))) {
            return std::nullopt;
        }
        sockaddr_in6 address{};
        std::memcpy(&address, &storage, sizeof(address));
        char text[INET6_ADDRSTRLEN]{};
        if (::inet_ntop(AF_INET6, &address.sin6_addr, text, sizeof(text)) == nullptr) {
            return std::nullopt;
        }
        return Endpoint{std::string(text), ntohs(address.sin6_port)};
    }
    return std::nullopt;
}

}  // namespace

bool operator==(const Endpoint& lhs, const Endpoint& rhs) noexcept {
    return lhs.port == rhs.port && lhs.address == rhs.address;
}

bool operator!=(const Endpoint& lhs, const Endpoint& rhs) noexcept { return !(lhs == rhs); }

FdResult listen_tcp(std::string_view address, std::uint16_t port, int backlog,
                    bool reuse_port) {
    FdResult result;

    sockaddr_storage storage{};
    socklen_t length = 0;
    if (!parse_endpoint(address, port, storage, length)) {
        result.error = EINVAL;
        return result;
    }

    const int fd = open_tcp_socket(storage.ss_family);
    if (fd < 0) {
        result.error = errno;
        return result;
    }
    UniqueFd owned(fd);

    const int enable = 1;
    if (::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable)) != 0) {
        result.error = errno;
        return result;
    }
    if (reuse_port &&
        ::setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &enable, sizeof(enable)) != 0) {
        result.error = errno;
        return result;
    }
    if (::bind(fd, reinterpret_cast<const sockaddr*>(&storage), length) != 0) {
        result.error = errno;
        return result;
    }
    // SOMAXCONN is a userspace (glibc) constant, not the kernel limit; Linux
    // silently caps the effective backlog at net.core.somaxconn. Clamp only to
    // the kernel's int range so a requested 1024 backlog is not cut to 128 here.
    if (::listen(fd, std::clamp(backlog, 1, 65535)) != 0) {
        result.error = errno;
        return result;
    }

    result.fd = std::move(owned);
    return result;
}

bool is_numeric_address(std::string_view address) noexcept {
    sockaddr_storage storage{};
    socklen_t length = 0;
    return parse_endpoint(address, 0, storage, length);
}

std::optional<std::string> resolve_numeric_host(std::string_view host) {
    if (is_numeric_address(host)) return std::string(host);

    std::string text(host);
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_ADDRCONFIG;
    addrinfo* list = nullptr;
    if (::getaddrinfo(text.c_str(), nullptr, &hints, &list) != 0) return std::nullopt;
    std::optional<std::string> out;
    for (const addrinfo* item = list; item != nullptr && !out; item = item->ai_next) {
        char buffer[INET6_ADDRSTRLEN] = {};
        if (item->ai_family == AF_INET) {
            const auto* v4 = reinterpret_cast<const sockaddr_in*>(item->ai_addr);
            if (::inet_ntop(AF_INET, &v4->sin_addr, buffer, sizeof(buffer)) != nullptr) out = buffer;
        } else if (item->ai_family == AF_INET6) {
            const auto* v6 = reinterpret_cast<const sockaddr_in6*>(item->ai_addr);
            if (::inet_ntop(AF_INET6, &v6->sin6_addr, buffer, sizeof(buffer)) != nullptr) out = buffer;
        }
    }
    ::freeaddrinfo(list);
    return out;
}

FdResult connect_tcp(std::string_view address, std::uint16_t port) {
    FdResult result;

    sockaddr_storage storage{};
    socklen_t length = 0;
    if (!parse_endpoint(address, port, storage, length)) {
        result.error = EINVAL;
        return result;
    }

    const int fd = open_tcp_socket(storage.ss_family);
    if (fd < 0) {
        result.error = errno;
        return result;
    }
    UniqueFd owned(fd);

    if (::connect(fd, reinterpret_cast<const sockaddr*>(&storage), length) == 0) {
        result.fd = std::move(owned);
        return result;
    }
    const int error = errno;
    if (error == EINPROGRESS || error == EALREADY || error == EINTR) {
        // The connection attempt continues asynchronously; the caller waits for
        // writability and checks SO_ERROR.
        result.in_progress = true;
        result.fd = std::move(owned);
        return result;
    }
    result.error = error;
    return result;
}

std::optional<Endpoint> local_endpoint(int fd) {
    if (fd < 0) {
        return std::nullopt;
    }
    sockaddr_storage storage{};
    socklen_t length = sizeof(storage);
    // The POSIX socket API requires the generic sockaddr pointer.
    if (::getsockname(fd, reinterpret_cast<sockaddr*>(&storage), &length) != 0) {
        return std::nullopt;
    }
    return endpoint_from(storage, length);
}

bool set_tcp_keepalive(int fd, int idle_seconds, int interval_seconds,
                       int probes) noexcept {
    if (fd < 0) return false;
    const int enable = 1;
    if (::setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &enable, sizeof(enable)) != 0) {
        return false;
    }
    bool ok = true;
    if (::setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE, &idle_seconds,
                     sizeof(idle_seconds)) != 0) {
        ok = false;
    }
    if (::setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, &interval_seconds,
                     sizeof(interval_seconds)) != 0) {
        ok = false;
    }
    if (::setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT, &probes, sizeof(probes)) != 0) {
        ok = false;
    }
    return ok;
}

bool set_tcp_user_timeout(int fd, unsigned timeout_ms) noexcept {
    if (fd < 0) return false;
    return ::setsockopt(fd, IPPROTO_TCP, TCP_USER_TIMEOUT, &timeout_ms,
                        sizeof(timeout_ms)) == 0;
}

bool set_tcp_nodelay(int fd) noexcept {
    if (fd < 0) return false;
    const int enable = 1;
    return ::setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &enable, sizeof(enable)) == 0;
}

std::optional<Endpoint> endpoint_from_address(const void* address, std::size_t length) {
    if (address == nullptr || length > sizeof(sockaddr_storage)) return std::nullopt;
    sockaddr_storage storage{};
    std::memcpy(&storage, address, length);
    return endpoint_from(storage, static_cast<socklen_t>(length));
}

std::optional<Endpoint> peer_endpoint(int fd) {
    if (fd < 0) {
        return std::nullopt;
    }
    sockaddr_storage storage{};
    socklen_t length = sizeof(storage);
    if (::getpeername(fd, reinterpret_cast<sockaddr*>(&storage), &length) != 0) {
        return std::nullopt;
    }
    return endpoint_from(storage, length);
}

}  // namespace mtdd::io
