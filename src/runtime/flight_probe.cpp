// Server probe: one ordinary TLS 1.3 handshake with the real server of a
// masked tls_domain, measuring the encrypted EncryptedExtensions..Finished
// flight that FakeTLS imitates with its single ApplicationData record, and
// reading the server's own ServerHello (suite, extension order, key-share
// group) that FakeTLS mirrors. Runs on MaskingResolver's background thread
// only.
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

#include <algorithm>
#include <array>
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

struct Observed {
    FlightCounter counter;
    ServerHelloCapture hello;
};

constexpr std::uint16_t kPqGroup = 0x11ec;

// Message callback: record headers feed the flight counter; the server's
// handshake messages (whole, header included) feed the ServerHello capture.
void on_message(int write_p, int, int content_type, const void* buf, std::size_t len, SSL*,
                void* arg) {
    auto* observed = static_cast<Observed*>(arg);
    if (content_type == SSL3_RT_HANDSHAKE && write_p == 0 && buf != nullptr) {
        observed->hello.observe(
            std::span<const std::uint8_t>(static_cast<const std::uint8_t*>(buf), len));
        return;
    }
    auto* counter = &observed->counter;
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

    // Reads one batch into `in` (nullptr: discard). 1 bytes (or a retryable
    // nothing), 0 EOF, -1 failure. `received` is set when bytes arrived.
    int fill(BIO* in, Clock::time_point until, Clock::time_point* received = nullptr) const {
        if (!wait(POLLIN, until)) return -1;
        std::array<char, 16384> buffer{};
        const ssize_t got = ::recv(fd_, buffer.data(), buffer.size(), 0);
        if (got > 0) {
            if (received != nullptr) *received = Clock::now();
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

std::optional<ServerProbe> handshake(int fd, const std::string& server_name,
                                     Clock::time_point deadline,
                                     const std::function<bool()>& cancelled, bool offer_pq) {
    const Probe probe(fd, deadline, cancelled);
    std::unique_ptr<SSL_CTX, SslFree> ctx(SSL_CTX_new(TLS_client_method()));
    if (!ctx) return std::nullopt;
    // What browsers (and the Telegram client's ClientHello) offer; the server
    // echoes the choice in EncryptedExtensions, which is part of the flight.
    static constexpr unsigned char kAlpn[] = "\x02h2\x08http/1.1";
    if (SSL_CTX_set_alpn_protos(ctx.get(), kAlpn, sizeof(kAlpn) - 1) != 0) return std::nullopt;
    // The Chrome/Telegram suite order: a server that honours the client's
    // order picks AES-128-GCM, one with its own preference shows it here.
    if (SSL_CTX_set_ciphersuites(ctx.get(), "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:"
                                            "TLS_CHACHA20_POLY1305_SHA256") != 1) {
        return std::nullopt;
    }
    // Key shares for both X25519MLKEM768 and X25519, as the Telegram client
    // sends them ('*' marks a key share, OpenSSL >= 3.5). Older OpenSSL, or a
    // build without ML-KEM, rejects the list: classical groups only then.
    const bool pq_offered =
        offer_pq &&
        SSL_CTX_set1_groups_list(ctx.get(), "*X25519MLKEM768:*X25519:secp256r1:secp384r1") == 1;
    if (!pq_offered) {
        ERR_clear_error();
        if (SSL_CTX_set1_groups_list(ctx.get(), "X25519:secp256r1:secp384r1") != 1) {
            return std::nullopt;
        }
    }
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
    Observed observed;
    SSL_set_msg_callback(ssl.get(), &on_message);
    SSL_set_msg_callback_arg(ssl.get(), &observed);

    // ClientHello fully written -> first byte of the answer: each write
    // (a ClientHello, a second one after HelloRetryRequest) restarts the
    // wait, and the first bytes read after it end it. The client's Finished
    // is the last write and is answered by nothing read here, so the last
    // completed pair is the latency of the final ServerHello.
    std::optional<Clock::time_point> written;
    std::optional<Clock::duration> latency;
    while (true) {
        const int status = SSL_connect(ssl.get());
        const bool sending = BIO_ctrl_pending(out) > 0;
        if (!probe.flush(out)) return std::nullopt;
        if (sending) written = Clock::now();
        if (status == 1) break;
        if (SSL_get_error(ssl.get(), status) != SSL_ERROR_WANT_READ) return std::nullopt;
        Clock::time_point received{};  // stays epoch when nothing arrived
        if (probe.fill(in, deadline, &received) != 1) return std::nullopt;
        if (written && received != Clock::time_point{}) {
            latency = received - *written;
            written.reset();
        }
    }
    std::optional<ServerProbe> result;
    const auto& counter = observed.counter;
    if (SSL_version(ssl.get()) == TLS1_3_VERSION && counter.done && counter.records > 0) {
        result.emplace();
        result->flight = counter.bodies + 5 * (counter.records - 1);
        result->retried = observed.hello.retried;
        if (latency) {
            result->hello_latency =
                std::chrono::duration_cast<std::chrono::microseconds>(*latency);
        }
        if (const auto& hello = observed.hello.hello) {
            result->cipher = hello->cipher;
            result->group = hello->group;
            result->extensions = hello->extensions;
            const auto& types = hello->extensions;
            const auto share = std::find(types.begin(), types.end(), std::uint16_t{0x0033});
            const auto versions = std::find(types.begin(), types.end(), std::uint16_t{0x002b});
            result->key_share_first =
                share != types.end() && versions != types.end() && share < versions;
            if (pq_offered && hello->group != 0) {
                result->pq = hello->group == kPqGroup ? PqAnswer::pq : PqAnswer::classical;
            }
        }
    }

    // close_notify and nothing else; then read until the server closes.
    SSL_shutdown(ssl.get());
    if (probe.flush(out)) {
        const auto until = Clock::now() + kDrainAfterClose;
        while (probe.fill(nullptr, until) == 1) {
        }
    }
    return result;
}

std::uint16_t read16(std::span<const std::uint8_t> bytes, std::size_t at) {
    return static_cast<std::uint16_t>((bytes[at] << 8) | bytes[at + 1]);
}

// SHA-256("HelloRetryRequest"), the random of every HelloRetryRequest.
constexpr std::array<std::uint8_t, 32> kRetryRandom{
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
    0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c};

}  // namespace

std::optional<ServerHelloFacts> parse_server_hello(std::span<const std::uint8_t> message) {
    // type(1) length(3) | legacy_version(2) random(32) session_id(1+n)
    // cipher_suite(2) compression(1) extensions(2+n)
    if (message.size() < 4 || message[0] != 0x02) return std::nullopt;
    const std::size_t length = (static_cast<std::size_t>(message[1]) << 16) |
                               (static_cast<std::size_t>(message[2]) << 8) | message[3];
    if (message.size() != 4 + length) return std::nullopt;
    const auto body = message.subspan(4);
    std::size_t pos = 2 + 32;
    if (body.size() < pos + 1) return std::nullopt;
    ServerHelloFacts facts;
    facts.retry = std::equal(kRetryRandom.begin(), kRetryRandom.end(), body.begin() + 2);
    const std::size_t session = body[pos];
    if (session > 32) return std::nullopt;
    pos += 1 + session;
    if (body.size() < pos + 2 + 1 + 2) return std::nullopt;
    facts.cipher = read16(body, pos);
    pos += 3;  // cipher_suite, legacy_compression_method
    const std::size_t extensions = read16(body, pos);
    pos += 2;
    if (body.size() != pos + extensions) return std::nullopt;
    while (pos < body.size()) {
        if (body.size() - pos < 4) return std::nullopt;
        const std::uint16_t type = read16(body, pos);
        const std::size_t size = read16(body, pos + 2);
        pos += 4;
        if (body.size() - pos < size) return std::nullopt;
        if (std::find(facts.extensions.begin(), facts.extensions.end(), type) !=
            facts.extensions.end()) {
            return std::nullopt;  // a repeated extension is malformed
        }
        facts.extensions.push_back(type);
        // key_share: KeyShareEntry (group, key) or, in an HRR, the group.
        if (type == 0x0033 && size >= 2) facts.group = read16(body, pos);
        pos += size;
    }
    return facts;
}

void ServerHelloCapture::observe(std::span<const std::uint8_t> message) {
    if (message.empty() || message[0] != 0x02) return;  // not a ServerHello
    auto facts = parse_server_hello(message);
    if (!facts) return;
    if (facts->retry) {
        retried = true;  // the real ServerHello follows the second ClientHello
        return;
    }
    hello = std::move(facts);
}

std::optional<ServerProbe> probe_server(const std::string& address, std::uint16_t port,
                                        const std::string& server_name,
                                        std::chrono::milliseconds timeout,
                                        const std::function<bool()>& cancelled, bool offer_pq) {
    if (cancelled && cancelled()) return std::nullopt;
    const auto started = Clock::now();
    const auto deadline = started + timeout;
    auto connection = io::connect_tcp(address, port);
    if (!connection.ok()) return std::nullopt;
    std::optional<ServerProbe> result;
    if (!connection.in_progress ||
        Probe(connection.fd.get(), deadline, cancelled).connected()) {
        // One TCP round trip (SYN -> SYN-ACK); an immediate connect is ~0.
        const auto connect_rtt =
            std::chrono::duration_cast<std::chrono::microseconds>(Clock::now() - started);
        result = handshake(connection.fd.get(), server_name, deadline, cancelled, offer_pq);
        if (result) {
            result->connect_rtt = connect_rtt;
            if (result->hello_latency) {
                result->processing = server_processing_time(connect_rtt, *result->hello_latency);
            }
        }
    }
    // OpenSSL's error queue is per thread; leave nothing behind on this one.
    ERR_clear_error();
    // A larger flight cannot fit the one record the client accepts: the
    // closest legal imitation is the largest record.
    if (result && result->flight < protocol::kServerFlightMin) return std::nullopt;
    if (result) result->flight = std::min(result->flight, protocol::kServerFlightMax);
    return result;
}

std::chrono::microseconds server_processing_time(std::chrono::microseconds connect_rtt,
                                                 std::chrono::microseconds hello_latency) {
    return std::max(hello_latency - connect_rtt, std::chrono::microseconds{0});
}

void ServerTimingHistory::add(std::chrono::microseconds sample) noexcept {
    samples_[next_] = std::max(sample, std::chrono::microseconds{0});
    next_ = (next_ + 1) % kCapacity;
    size_ = std::min(size_ + 1, kCapacity);
}

std::optional<ServerTiming> ServerTimingHistory::summary() const {
    if (size_ == 0) return std::nullopt;
    std::array<std::chrono::microseconds, kCapacity> sorted{};
    std::copy_n(samples_.begin(), size_, sorted.begin());
    std::sort(sorted.begin(), sorted.begin() + static_cast<std::ptrdiff_t>(size_));
    // Quantile num/4 with linear interpolation between neighbours.
    const auto quantile = [&](std::size_t num) {
        const std::size_t scaled = num * (size_ - 1);
        const std::size_t index = scaled / 4;
        const std::size_t rest = scaled % 4;
        auto value = sorted[index];
        if (rest != 0) {
            value += (sorted[index + 1] - sorted[index]) * static_cast<std::int64_t>(rest) / 4;
        }
        return value;
    };
    return ServerTiming{quantile(1), quantile(2), quantile(3), size_};
}

ServerHelloDelayChoice pick_server_hello_delay(const Config& config,
                                               const std::optional<ServerTiming>& timing,
                                               std::uint32_t draw) noexcept {
    using std::chrono::microseconds;
    ServerHelloDelayChoice choice;
    const auto low = config.server_hello_delay_min;
    const auto high = std::max(config.server_hello_delay_max, low);
    if (high.count() > 0) {
        // Manual bounds win; a whole-millisecond draw as before.
        const auto span = static_cast<std::uint64_t>((high - low).count()) + 1U;
        choice.delay = low + std::chrono::milliseconds(static_cast<std::int64_t>(draw % span));
        return choice;
    }
    if (!config.server_hello_delay_auto || !timing) return choice;
    const microseconds cap = Config::kMaxAutoServerHelloDelay;
    const auto from = std::clamp(timing->low, microseconds{0}, cap);
    const auto to = std::clamp(std::max(timing->high, timing->low), microseconds{0}, cap);
    const auto span = static_cast<std::uint64_t>((to - from).count()) + 1U;
    choice.delay = from + microseconds(static_cast<std::int64_t>(draw % span));
    choice.automatic = true;
    return choice;
}

std::optional<std::size_t> measure_server_flight(const std::string& address, std::uint16_t port,
                                                 const std::string& server_name,
                                                 std::chrono::milliseconds timeout,
                                                 const std::function<bool()>& cancelled) {
    const auto result = probe_server(address, port, server_name, timeout, cancelled);
    if (!result) return std::nullopt;
    return result->flight;
}

}  // namespace mtdd::detail
