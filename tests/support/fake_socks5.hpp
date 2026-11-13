// Loopback SOCKS5 proxy for the upstream tests: RFC 1928 CONNECT (IPv4/IPv6
// targets), optional RFC 1929 username/password, then a byte relay. Every
// session runs on its own thread; the reply's BND.ADDR/PORT is the local end
// of the proxy's own connection to the target, as a real proxy reports it.
#pragma once

#include "mtdd/io.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

namespace mtdd::test {

struct FakeSocks5Options {
    std::string username;  // empty: no authentication
    std::string password;
    std::uint8_t connect_reply{0};  // non-zero: refuse CONNECT with this code
};

class FakeSocks5 {
public:
    using Options = FakeSocks5Options;

    FakeSocks5() : FakeSocks5(Options{}) {}
    explicit FakeSocks5(Options options) : options_(std::move(options)) {
        auto listener = io::listen_tcp("127.0.0.1", 0);
        if (!listener.ok()) throw std::runtime_error("fake SOCKS5 cannot listen");
        listener_ = std::move(listener.fd);
        const auto local = io::local_endpoint(listener_.get());
        if (!local) throw std::runtime_error("fake SOCKS5 has no port");
        port_ = local->port;
        accept_thread_ = std::thread([this] { run(); });
    }
    ~FakeSocks5() {
        stop_.store(true);
        if (accept_thread_.joinable()) accept_thread_.join();
        std::vector<std::thread> sessions;
        {
            std::lock_guard lock(mutex_);
            sessions.swap(sessions_);
        }
        for (auto& session : sessions) {
            if (session.joinable()) session.join();
        }
    }
    FakeSocks5(const FakeSocks5&) = delete;
    FakeSocks5& operator=(const FakeSocks5&) = delete;

    std::uint16_t port() const { return port_; }
    std::string address() const { return "127.0.0.1:" + std::to_string(port_); }
    std::uint64_t connects() const { return connects_.load(); }
    std::uint64_t auth_failures() const { return auth_failures_.load(); }
    std::vector<std::uint16_t> target_ports() const {
        std::lock_guard lock(mutex_);
        return target_ports_;
    }

private:
    static bool read_exact(int fd, std::uint8_t* data, std::size_t size) {
        std::size_t got = 0;
        while (got < size) {
            pollfd entry{fd, POLLIN, 0};
            if (::poll(&entry, 1, 3000) <= 0) return false;
            const ssize_t n = ::recv(fd, data + got, size - got, 0);
            if (n <= 0) return false;
            got += static_cast<std::size_t>(n);
        }
        return true;
    }
    static bool write_all(int fd, const std::uint8_t* data, std::size_t size) {
        std::size_t sent = 0;
        while (sent < size) {
            const ssize_t n = ::send(fd, data + sent, size - sent, MSG_NOSIGNAL);
            if (n <= 0) return false;
            sent += static_cast<std::size_t>(n);
        }
        return true;
    }

    void run() {
        while (!stop_.load()) {
            pollfd entry{listener_.get(), POLLIN, 0};
            if (::poll(&entry, 1, 50) <= 0 || (entry.revents & POLLIN) == 0) continue;
            const int fd = ::accept4(listener_.get(), nullptr, nullptr, SOCK_CLOEXEC);
            if (fd < 0) continue;
            std::lock_guard lock(mutex_);
            sessions_.emplace_back([this, fd] {
                session(fd);
                ::close(fd);
            });
        }
    }

    void session(int client) {
        std::uint8_t head[2]{};
        if (!read_exact(client, head, 2) || head[0] != 5 || head[1] == 0) return;
        std::vector<std::uint8_t> methods(head[1]);
        if (!read_exact(client, methods.data(), methods.size())) return;
        const std::uint8_t wanted = options_.username.empty() ? 0x00 : 0x02;
        bool offered = false;
        for (const auto method : methods) offered = offered || method == wanted;
        const std::uint8_t choice[2]{5, offered ? wanted : std::uint8_t{0xff}};
        if (!write_all(client, choice, 2) || !offered) return;
        if (wanted == 0x02) {
            std::uint8_t version_len[2]{};
            if (!read_exact(client, version_len, 2) || version_len[0] != 1) return;
            std::string user(version_len[1], '\0');
            if (!read_exact(client, reinterpret_cast<std::uint8_t*>(user.data()), user.size())) return;
            std::uint8_t plen = 0;
            if (!read_exact(client, &plen, 1)) return;
            std::string pass(plen, '\0');
            if (!read_exact(client, reinterpret_cast<std::uint8_t*>(pass.data()), pass.size())) return;
            const bool ok = user == options_.username && pass == options_.password;
            const std::uint8_t status[2]{1, ok ? std::uint8_t{0} : std::uint8_t{1}};
            if (!ok) ++auth_failures_;
            if (!write_all(client, status, 2) || !ok) return;
        }
        std::uint8_t request[4]{};
        if (!read_exact(client, request, 4) || request[0] != 5 || request[1] != 1) return;
        sockaddr_storage target{};
        socklen_t target_length = 0;
        std::uint16_t port = 0;
        if (request[3] == 1) {
            std::uint8_t body[6]{};
            if (!read_exact(client, body, 6)) return;
            auto* v4 = reinterpret_cast<sockaddr_in*>(&target);
            v4->sin_family = AF_INET;
            std::memcpy(&v4->sin_addr, body, 4);
            std::memcpy(&v4->sin_port, body + 4, 2);
            port = ntohs(v4->sin_port);
            target_length = sizeof(sockaddr_in);
        } else if (request[3] == 4) {
            std::uint8_t body[18]{};
            if (!read_exact(client, body, 18)) return;
            auto* v6 = reinterpret_cast<sockaddr_in6*>(&target);
            v6->sin6_family = AF_INET6;
            std::memcpy(&v6->sin6_addr, body, 16);
            std::memcpy(&v6->sin6_port, body + 16, 2);
            port = ntohs(v6->sin6_port);
            target_length = sizeof(sockaddr_in6);
        } else {
            return;
        }
        {
            std::lock_guard lock(mutex_);
            target_ports_.push_back(port);
        }
        ++connects_;
        if (options_.connect_reply != 0) {
            const std::uint8_t refused[10]{5, options_.connect_reply, 0, 1, 0, 0, 0, 0, 0, 0};
            (void)write_all(client, refused, sizeof(refused));
            return;
        }
        const int upstream = ::socket(target.ss_family, SOCK_STREAM | SOCK_CLOEXEC, 0);
        if (upstream < 0) return;
        if (::connect(upstream, reinterpret_cast<const sockaddr*>(&target), target_length) != 0) {
            const std::uint8_t refused[10]{5, 5, 0, 1, 0, 0, 0, 0, 0, 0};
            (void)write_all(client, refused, sizeof(refused));
            ::close(upstream);
            return;
        }
        sockaddr_storage bound{};
        socklen_t bound_length = sizeof(bound);
        ::getsockname(upstream, reinterpret_cast<sockaddr*>(&bound), &bound_length);
        std::vector<std::uint8_t> reply{5, 0, 0};
        if (bound.ss_family == AF_INET6) {
            const auto* v6 = reinterpret_cast<const sockaddr_in6*>(&bound);
            reply.push_back(4);
            const auto* bytes = reinterpret_cast<const std::uint8_t*>(&v6->sin6_addr);
            reply.insert(reply.end(), bytes, bytes + 16);
            const auto* port_bytes = reinterpret_cast<const std::uint8_t*>(&v6->sin6_port);
            reply.insert(reply.end(), port_bytes, port_bytes + 2);
        } else {
            const auto* v4 = reinterpret_cast<const sockaddr_in*>(&bound);
            reply.push_back(1);
            const auto* bytes = reinterpret_cast<const std::uint8_t*>(&v4->sin_addr);
            reply.insert(reply.end(), bytes, bytes + 4);
            const auto* port_bytes = reinterpret_cast<const std::uint8_t*>(&v4->sin_port);
            reply.insert(reply.end(), port_bytes, port_bytes + 2);
        }
        if (write_all(client, reply.data(), reply.size())) relay(client, upstream);
        ::close(upstream);
    }

    void relay(int a, int b) {
        std::uint8_t buffer[16384];
        bool a_open = true;
        bool b_open = true;
        while (!stop_.load() && (a_open || b_open)) {
            pollfd entries[2]{{a, static_cast<short>(a_open ? POLLIN : 0), 0},
                              {b, static_cast<short>(b_open ? POLLIN : 0), 0}};
            if (::poll(entries, 2, 50) <= 0) continue;
            for (int i = 0; i < 2; ++i) {
                if ((entries[i].revents & (POLLIN | POLLHUP | POLLERR)) == 0) continue;
                const int from = i == 0 ? a : b;
                const int to = i == 0 ? b : a;
                const ssize_t n = ::recv(from, buffer, sizeof(buffer), 0);
                if (n > 0) {
                    if (!write_all(to, buffer, static_cast<std::size_t>(n))) return;
                } else {
                    ::shutdown(to, SHUT_WR);
                    (i == 0 ? a_open : b_open) = false;
                }
            }
        }
    }

    Options options_;
    io::UniqueFd listener_;
    std::uint16_t port_{0};
    std::atomic<bool> stop_{false};
    std::atomic<std::uint64_t> connects_{0};
    std::atomic<std::uint64_t> auth_failures_{0};
    mutable std::mutex mutex_;
    std::vector<std::uint16_t> target_ports_;
    std::vector<std::thread> sessions_;
    std::thread accept_thread_;
};

}  // namespace mtdd::test
