// Server-flight probe: one ordinary TLS 1.3 handshake with the real server of
// a masked tls_domain, measuring the encrypted EncryptedExtensions..Finished
// flight that FakeTLS imitates with its single ApplicationData record. Runs on
// MaskingResolver's background thread only.
//
// The TLS engine works on memory BIOs and this file moves the bytes, so every
// socket write uses MSG_NOSIGNAL (a peer reset cannot raise SIGPIPE) and every
// wait is a poll() slice that honours the deadline and cancellation.
#include "internal.hpp"

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

#include <poll.h>
#include <sys/socket.h>

#include <cerrno>

namespace mtdd::detail {

namespace {

using Clock = std::chrono::steady_clock;

// After close_notify, how long the server's last records (session tickets,
// its own close_notify) are read and discarded, so that closing is a FIN and
// not a RST for unread bytes.
constexpr std::chrono::milliseconds kDrainAfterClose{500};
constexpr std::chrono::milliseconds kPollSlice{100};

// Record-header callback: sums the ApplicationData records the server sends
// after its (last) ServerHello until the client writes again, which happens
// only once the server's Finished has been processed. A HelloRetryRequest is
// followed by a second ClientHello before any ApplicationData, so it restarts
// nothing that was counted.
struct FlightCounter {
    std::size_t bodies{0};
    std::size_t records{0};
    bool counting{false};
    bool done{false};
};

void on_record(int write_p, int, int content_type, const void* buf, std::size_t len, SSL*,
               void* arg) {
    auto* counter = static_cast<FlightCounter*>(arg);
    if (content_type != SSL3_RT_HEADER || len < 5 || counter->done) return;
    const auto* header = static_cast<const std::uint8_t*>(buf);
    if (write_p != 0) {
        if (counter->records > 0) counter->done = true;
        counter->counting = false;
        return;
    }
    if (header[0] == 0x16) {
        counter->counting = true;
        counter->bodies = 0;
        counter->records = 0;
    } else if (header[0] == 0x17 && counter->counting) {
        counter->bodies += (static_cast<std::size_t>(header[3]) << 8) | header[4];
        ++counter->records;
    }
}

struct SslFree {
    void operator()(SSL* ssl) const noexcept { SSL_free(ssl); }
    void operator()(SSL_CTX* ctx) const noexcept { SSL_CTX_free(ctx); }
};

class Probe {
public:
    Probe(int fd, Clock::time_point deadline, const std::function<bool()>& cancelled)
        : fd_(fd), deadline_(deadline), cancelled_(cancelled) {}

    // Waits for `events` until `until` (capped by the deadline) or cancellation.
    bool wait(short events, Clock::time_point until) const {
        until = std::min(until, deadline_);
        while (true) {
            if (cancelled_ && cancelled_()) return false;
            const auto now = Clock::now();
            if (now >= until) return false;
            const auto left =
                std::chrono::ceil<std::chrono::milliseconds>(until - now);
            pollfd entry{fd_, events, 0};
            const int ready =
                ::poll(&entry, 1, static_cast<int>(std::min(left, kPollSlice).count()));
            if (ready > 0) return true;  // POLLERR/POLLHUP: the next call reports it
            if (ready < 0 && errno != EINTR) return false;
        }
    }

    // Sends everything the TLS engine has queued.
    bool flush(BIO* out) const {
        std::array<char, 4096> buffer{};
        while (BIO_ctrl_pending(out) > 0) {
            const int got = BIO_read(out, buffer.data(), static_cast<int>(buffer.size()));
            if (got <= 0) return false;
            std::size_t sent = 0;
            while (sent < static_cast<std::size_t>(got)) {
                const ssize_t n = ::send(fd_, buffer.data() + sent,
                                         static_cast<std::size_t>(got) - sent, MSG_NOSIGNAL);
                if (n > 0) {
                    sent += static_cast<std::size_t>(n);
                } else if (n < 0 && errno == EINTR) {
                    continue;
                } else if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                    if (!wait(POLLOUT, deadline_)) return false;
                } else {
                    return false;
                }
            }
        }
        return true;
    }

    // Reads one batch into `in` (nullptr: discard). 1 bytes, 0 EOF, -1 failure.
    int fill(BIO* in, Clock::time_point until) const {
        if (!wait(POLLIN, until)) return -1;
        std::array<char, 16384> buffer{};
        const ssize_t got = ::recv(fd_, buffer.data(), buffer.size(), 0);
        if (got > 0) {
            if (in != nullptr && BIO_write(in, buffer.data(), static_cast<int>(got)) != got) {
                return -1;
            }
            return 1;
        }
        if (got == 0) return 0;
        return (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) ? 1 : -1;
    }

    bool connected() const {
        if (!wait(POLLOUT, deadline_)) return false;
        int error = 0;
        socklen_t length = sizeof(error);
        return ::getsockopt(fd_, SOL_SOCKET, SO_ERROR, &error, &length) == 0 && error == 0;
    }

private:
    int fd_;
    Clock::time_point deadline_;
    const std::function<bool()>& cancelled_;
};

std::optional<std::size_t> handshake(int fd, const std::string& server_name,
                                     Clock::time_point deadline,
                                     const std::function<bool()>& cancelled) {
    const Probe probe(fd, deadline, cancelled);
    std::unique_ptr<SSL_CTX, SslFree> ctx(SSL_CTX_new(TLS_client_method()));
    if (!ctx) return std::nullopt;
    // What browsers (and the Telegram client's ClientHello) offer; the server
    // echoes the choice in EncryptedExtensions, which is part of the flight.
    static constexpr unsigned char kAlpn[] = "\x02h2\x08http/1.1";
    if (SSL_CTX_set_alpn_protos(ctx.get(), kAlpn, sizeof(kAlpn) - 1) != 0) return std::nullopt;
    std::unique_ptr<SSL, SslFree> ssl(SSL_new(ctx.get()));
    BIO* in = BIO_new(BIO_s_mem());
    BIO* out = BIO_new(BIO_s_mem());
    if (!ssl || in == nullptr || out == nullptr) {
        BIO_free(in);
        BIO_free(out);
        return std::nullopt;
    }
    BIO_set_mem_eof_return(in, -1);  // empty means "want more", not EOF
    SSL_set_bio(ssl.get(), in, out);  // owned by ssl from here on
    if (SSL_set_tlsext_host_name(ssl.get(), server_name.c_str()) != 1) return std::nullopt;
    FlightCounter counter;
    SSL_set_msg_callback(ssl.get(), &on_record);
    SSL_set_msg_callback_arg(ssl.get(), &counter);

    while (true) {
        const int status = SSL_connect(ssl.get());
        if (!probe.flush(out)) return std::nullopt;
        if (status == 1) break;
        if (SSL_get_error(ssl.get(), status) != SSL_ERROR_WANT_READ) return std::nullopt;
        if (probe.fill(in, deadline) != 1) return std::nullopt;
    }
    std::optional<std::size_t> flight;
    if (SSL_version(ssl.get()) == TLS1_3_VERSION && counter.done && counter.records > 0) {
        flight = counter.bodies + 5 * (counter.records - 1);
    }

    // close_notify and nothing else; then read until the server closes.
    SSL_shutdown(ssl.get());
    if (probe.flush(out)) {
        const auto until = Clock::now() + kDrainAfterClose;
        while (probe.fill(nullptr, until) == 1) {
        }
    }
    return flight;
}

}  // namespace

std::optional<std::size_t> measure_server_flight(const std::string& address, std::uint16_t port,
                                                 const std::string& server_name,
                                                 std::chrono::milliseconds timeout,
                                                 const std::function<bool()>& cancelled) {
    if (cancelled && cancelled()) return std::nullopt;
    const auto deadline = Clock::now() + timeout;
    auto connection = io::connect_tcp(address, port);
    if (!connection.ok()) return std::nullopt;
    std::optional<std::size_t> flight;
    if (!connection.in_progress ||
        Probe(connection.fd.get(), deadline, cancelled).connected()) {
        flight = handshake(connection.fd.get(), server_name, deadline, cancelled);
    }
    // OpenSSL's error queue is per thread; leave nothing behind on this one.
    ERR_clear_error();
    // A larger flight cannot fit the one record the client accepts: the
    // closest legal imitation is the largest record.
    if (flight && *flight < protocol::kServerFlightMin) return std::nullopt;
    if (flight) flight = std::min(*flight, protocol::kServerFlightMax);
    return flight;
}

}  // namespace mtdd::detail
