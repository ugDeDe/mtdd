#include "../support/runtime_fixture.hpp"

#include <sys/ioctl.h>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <map>
#include <set>

// ---------------------------------------------------------------------------
// Server-flight probe: the background masking thread measures the encrypted
// first flight of each masked tls_domain with a real TLS 1.3 handshake, and
// FakeTLS ServerHellos then carry that length (per user domain). The real
// domain is never reached: the masking endpoint override sends every probe to
// a local OpenSSL TLS 1.3 server with self-signed certificates made here.
// ---------------------------------------------------------------------------

namespace {

constexpr std::string_view kFront = "front.test";
constexpr std::string_view kBobSecretHex = "101112131415161718191a1b1c1d1e1f";

using PKey = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
using Cert = std::unique_ptr<X509, decltype(&X509_free)>;

// Self-signed Ed25519 certificate (constant-size signatures, so the flight
// size is the same on every handshake). `extra_names` subjectAltNames make
// one domain's certificate, and therefore its flight, larger than another's.
std::pair<PKey, Cert> self_signed(std::string_view name, int extra_names) {
    PKey key(EVP_PKEY_Q_keygen(nullptr, nullptr, "ED25519"), &EVP_PKEY_free);
    Cert cert(X509_new(), &X509_free);
    if (!key || !cert) throw std::runtime_error("cannot create test certificate");
    X509_set_version(cert.get(), 2);
    ASN1_INTEGER_set(X509_get_serialNumber(cert.get()), 1);
    X509_gmtime_adj(X509_getm_notBefore(cert.get()), -3600);
    X509_gmtime_adj(X509_getm_notAfter(cert.get()), 3600);
    X509_set_pubkey(cert.get(), key.get());
    X509_NAME* subject = X509_get_subject_name(cert.get());
    const std::string cn(name);
    X509_NAME_add_entry_by_txt(subject, "CN", MBSTRING_ASC,
                               reinterpret_cast<const unsigned char*>(cn.c_str()), -1, -1, 0);
    X509_set_issuer_name(cert.get(), subject);
    std::string san = "DNS:" + cn;
    for (int i = 0; i < extra_names; ++i) san += ",DNS:alt" + std::to_string(i) + "." + cn;
    X509V3_CTX v3{};
    X509V3_set_ctx_nodb(&v3);
    X509V3_set_ctx(&v3, cert.get(), cert.get(), nullptr, nullptr, 0);
    X509_EXTENSION* ext = X509V3_EXT_conf_nid(nullptr, &v3, NID_subject_alt_name, san.c_str());
    if (ext == nullptr) throw std::runtime_error("cannot add subjectAltName");
    X509_add_ext(cert.get(), ext, -1);
    X509_EXTENSION_free(ext);
    if (X509_sign(cert.get(), key.get(), nullptr) <= 0) throw std::runtime_error("cannot sign");
    return {std::move(key), std::move(cert)};
}

// How the local server negotiates (nullptr: OpenSSL defaults).
struct ServerTls {
    const char* suites{nullptr};
    bool server_preference{false};
    const char* groups{nullptr};
    // Held before answering each ClientHello: the server's processing time.
    std::chrono::milliseconds processing{0};
};

// TLS 1.3-only OpenSSL server on 127.0.0.1, one connection at a time. It
// computes, from its own record callback, the flight the probe must report
// for each SNI: the ApplicationData records it writes before reading the
// client's Finished, as one record body (sum of bodies + 5 per extra header).
// In `stall` mode it accepts TCP and never answers.
class LocalTlsServer {
public:
    enum class Mode { serve, stall };

    explicit LocalTlsServer(Mode mode = Mode::serve, ServerTls tls = {})
        : mode_(mode), processing_(tls.processing) {
        auto global = self_signed(kDomain, 0);
        auto front = self_signed(kFront, 40);
        global_key_ = std::move(global.first);
        global_cert_ = std::move(global.second);
        front_key_ = std::move(front.first);
        front_cert_ = std::move(front.second);
        ctx_.reset(SSL_CTX_new(TLS_server_method()));
        if (!ctx_) throw std::runtime_error("SSL_CTX_new");
        SSL_CTX_set_min_proto_version(ctx_.get(), TLS1_3_VERSION);
        if (tls.suites != nullptr && SSL_CTX_set_ciphersuites(ctx_.get(), tls.suites) != 1) {
            throw std::runtime_error("SSL_CTX_set_ciphersuites");
        }
        if (tls.server_preference) SSL_CTX_set_options(ctx_.get(), SSL_OP_CIPHER_SERVER_PREFERENCE);
        if (tls.groups != nullptr && SSL_CTX_set1_groups_list(ctx_.get(), tls.groups) != 1) {
            throw std::runtime_error("SSL_CTX_set1_groups_list");
        }
        SSL_CTX_use_certificate(ctx_.get(), global_cert_.get());
        SSL_CTX_use_PrivateKey(ctx_.get(), global_key_.get());
        SSL_CTX_set_tlsext_servername_callback(ctx_.get(), &LocalTlsServer::on_servername);
        SSL_CTX_set_tlsext_servername_arg(ctx_.get(), this);

        auto listener = mtdd::io::listen_tcp("127.0.0.1", 0);
        if (!listener.ok()) throw std::runtime_error("tls server cannot listen");
        listener_ = std::move(listener.fd);
        port_ = mtdd::io::local_endpoint(listener_.get())->port;
        thread_ = std::thread([this] { accept_loop(); });
    }
    ~LocalTlsServer() {
        stop_.store(true);
        if (thread_.joinable()) thread_.join();
        for (const int fd : stalled_) ::close(fd);
    }
    LocalTlsServer(const LocalTlsServer&) = delete;
    LocalTlsServer& operator=(const LocalTlsServer&) = delete;

    std::uint16_t port() const { return port_; }
    std::uint64_t accepted() const { return accepted_.load(); }
    std::optional<std::size_t> flight_for(std::string_view sni) const {
        const std::lock_guard lock{mutex_};
        const auto found = flights_.find(std::string(sni));
        if (found == flights_.end()) return std::nullopt;
        return found->second;
    }
    std::uint64_t handshakes(std::string_view sni) const {
        const std::lock_guard lock{mutex_};
        const auto found = handshakes_.find(std::string(sni));
        return found == handshakes_.end() ? 0 : found->second;
    }
    std::set<std::string> server_names() const {
        const std::lock_guard lock{mutex_};
        std::set<std::string> out;
        for (const auto& [name, count] : handshakes_) out.insert(name);
        return out;
    }

private:
    struct Flight {
        std::size_t bodies{0};
        std::size_t records{0};
        bool done{false};
    };

    static int on_servername(SSL* ssl, int*, void* arg) {
        auto* self = static_cast<LocalTlsServer*>(arg);
        if (self->processing_.count() > 0) std::this_thread::sleep_for(self->processing_);
        const char* name = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
        if (name != nullptr && std::string_view(name) == kFront) {
            SSL_use_certificate(ssl, self->front_cert_.get());
            SSL_use_PrivateKey(ssl, self->front_key_.get());
        }
        return SSL_TLSEXT_ERR_OK;
    }
    static void on_record(int write_p, int, int content_type, const void* buf, std::size_t len,
                          SSL*, void* arg) {
        auto* flight = static_cast<Flight*>(arg);
        if (content_type != SSL3_RT_HEADER || len < 5 || flight->done) return;
        const auto* header = static_cast<const std::uint8_t*>(buf);
        if (write_p == 0) {
            if (flight->records > 0) flight->done = true;  // the client's Finished
            return;
        }
        if (header[0] != 0x17) return;
        flight->bodies += (static_cast<std::size_t>(header[3]) << 8) | header[4];
        ++flight->records;
    }

    void accept_loop() {
        while (!stop_.load()) {
            pollfd entry{listener_.get(), POLLIN, 0};
            if (::poll(&entry, 1, 50) <= 0) continue;
            const int fd = ::accept4(listener_.get(), nullptr, nullptr, SOCK_CLOEXEC);
            if (fd < 0) continue;
            ++accepted_;
            if (mode_ == Mode::stall) {
                stalled_.push_back(fd);
                continue;
            }
            serve(fd);
            ::close(fd);
        }
    }
    void serve(int fd) {
        timeval timeout{};
        timeout.tv_sec = 3;
        ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
        ::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
        std::unique_ptr<SSL, decltype(&SSL_free)> ssl(SSL_new(ctx_.get()), &SSL_free);
        Flight flight;
        SSL_set_msg_callback(ssl.get(), &LocalTlsServer::on_record);
        SSL_set_msg_callback_arg(ssl.get(), &flight);
        SSL_set_fd(ssl.get(), fd);
        if (SSL_accept(ssl.get()) != 1) return;
        const char* name = SSL_get_servername(ssl.get(), TLSEXT_NAMETYPE_host_name);
        {
            const std::lock_guard lock{mutex_};
            const std::string sni = name ? name : "";
            flights_[sni] = flight.bodies + 5 * (flight.records - 1);
            ++handshakes_[sni];
        }
        // The probe sends close_notify and nothing else.
        std::array<char, 256> buffer{};
        const int got = SSL_read(ssl.get(), buffer.data(), static_cast<int>(buffer.size()));
        if (got <= 0) SSL_shutdown(ssl.get());
    }

    Mode mode_;
    std::chrono::milliseconds processing_;
    PKey global_key_{nullptr, &EVP_PKEY_free};
    Cert global_cert_{nullptr, &X509_free};
    PKey front_key_{nullptr, &EVP_PKEY_free};
    Cert front_cert_{nullptr, &X509_free};
    std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)> ctx_{nullptr, &SSL_CTX_free};
    mtdd::io::UniqueFd listener_;
    std::uint16_t port_{0};
    std::atomic<bool> stop_{false};
    std::atomic<std::uint64_t> accepted_{0};
    std::vector<int> stalled_;  // accept thread only, then the destructor
    mutable std::mutex mutex_;
    std::map<std::string, std::size_t> flights_;
    std::map<std::string, std::uint64_t> handshakes_;
    std::thread thread_;
};

// Every automatic masking target dials `port`; the first server-flight probe
// starts at once; any DNS lookup is counted (the override must need none).
struct ProbeScope {
    explicit ProbeScope(std::uint16_t port) {
        mtdd::detail::set_masking_endpoint_override(
            mtdd::detail::DirectEndpointOverride{"127.0.0.1", port});
        mtdd::detail::MaskingResolveHooks hooks;
        hooks.resolve = [this](const std::string&) -> std::optional<std::string> {
            ++lookups;
            return std::nullopt;
        };
        hooks.probe_delay = 0ms;
        mtdd::detail::set_masking_resolve_hooks_for_test(std::move(hooks));
    }
    ~ProbeScope() {
        mtdd::detail::set_masking_resolve_hooks_for_test(std::nullopt);
        mtdd::detail::set_masking_endpoint_override(std::nullopt);
    }
    ProbeScope(const ProbeScope&) = delete;
    ProbeScope& operator=(const ProbeScope&) = delete;

    std::atomic<std::uint64_t> lookups{0};
};

std::uint16_t closed_port() {
    auto listener = mtdd::io::listen_tcp("127.0.0.1", 0);
    if (!listener.ok()) throw std::runtime_error("cannot listen");
    return mtdd::io::local_endpoint(listener.fd.get())->port;  // closed on return
}

// One authenticated FakeTLS hello; the body length of the ApplicationData
// record after ServerHello + CCS, or nullopt.
std::optional<std::size_t> app_data_length(std::uint16_t port, const A16& secret,
                                           std::string_view sni) {
    const int fd = connect_loopback(port);
    if (fd < 0) return std::nullopt;
    const auto ts = static_cast<std::uint32_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch())
            .count());
    // A fresh client random each time: a repeated hello would be a replay.
    static std::atomic<unsigned> variant{0};
    const auto hello =
        make_client_hello(secret, ts, sni, static_cast<std::uint8_t>(variant.fetch_add(1)));
    std::optional<std::size_t> out;
    std::array<std::uint8_t, 5> header{};
    if (send_all(fd, hello) &&
        recv_exact(fd, header.data(), header.size(), 2000) && header[0] == 0x16) {
        Bytes rest((static_cast<std::size_t>(header[3]) << 8 | header[4]) + 6);
        std::array<std::uint8_t, 5> app{};
        if (recv_exact(fd, rest.data(), rest.size(), 2000) &&
            recv_exact(fd, app.data(), app.size(), 2000) && app[0] == 0x17) {
            out = static_cast<std::size_t>(app[3]) << 8 | app[4];
        }
    }
    ::close(fd);
    return out;
}

void masking_on(mtdd::Config& config) { config.masking = true; }

// Within kServerFlightJitter of the measured `flight`.
bool near(std::optional<std::size_t> length, std::size_t flight) {
    return length && *length + mtdd::detail::kServerFlightJitter >= flight &&
           *length <= flight + mtdd::detail::kServerFlightJitter;
}

bool in_fallback_range(std::optional<std::size_t> length) {
    return length && *length >= mtdd::protocol::kServerFlightFallbackMin &&
           *length <= mtdd::protocol::kServerFlightFallbackMax;
}

using mtdd::detail::PqAnswer;

// Whether the linked OpenSSL can offer X25519MLKEM768 key shares (>= 3.5);
// otherwise the probe offers classical groups only and reports `unknown`.
bool openssl_offers_pq() {
    std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)> ctx(SSL_CTX_new(TLS_client_method()),
                                                          &SSL_CTX_free);
    const bool ok = ctx && SSL_CTX_set1_groups_list(ctx.get(), "*X25519MLKEM768:*X25519") == 1;
    ERR_clear_error();
    return ok;
}

PqAnswer declined() { return openssl_offers_pq() ? PqAnswer::classical : PqAnswer::unknown; }

constexpr const char* kChachaFirst =
    "TLS_CHACHA20_POLY1305_SHA256:TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256";
const std::vector<std::uint16_t> kVersionsThenShare{0x002b, 0x0033};

// The daemon's ServerHello to one authenticated hello: suite, extension types
// in order, key_share group.
struct Answer {
    std::uint16_t cipher{0};
    std::vector<std::uint16_t> extensions;
    std::uint16_t group{0};
};
std::optional<Answer> daemon_answer(std::uint16_t port, bool offer_pq) {
    const int fd = connect_loopback(port);
    if (fd < 0) return std::nullopt;
    const auto ts = static_cast<std::uint32_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch())
            .count());
    static std::atomic<unsigned> variant{100};
    const auto hello = make_client_hello(secret_bytes(), ts, kDomain,
                                         static_cast<std::uint8_t>(variant.fetch_add(1)), offer_pq);
    std::optional<Answer> out;
    std::array<std::uint8_t, 5> header{};
    if (send_all(fd, hello) && recv_exact(fd, header.data(), header.size(), 2000) &&
        header[0] == 0x16) {
        Bytes record(header.begin(), header.end());
        record.resize(5 + (static_cast<std::size_t>(header[3]) << 8 | header[4]));
        if (record.size() >= 81 && recv_exact(fd, record.data() + 5, record.size() - 5, 2000)) {
            if (auto facts = mtdd::detail::parse_server_hello(
                    std::span<const std::uint8_t>(record).subspan(5))) {
                out = Answer{facts->cipher, facts->extensions, facts->group};
            }
        }
    }
    ::close(fd);
    return out;
}

Bytes cat_bytes(const Bytes& first, const Bytes& second) {
    Bytes out = first;
    append(out, second);
    return out;
}

// A raw ServerHello handshake message: legacy_version, random, a 32-byte
// session id, `cipher`, null compression, then `extensions` as given.
Bytes server_hello_message(const std::array<std::uint8_t, 32>& random, std::uint16_t cipher,
                           const Bytes& extensions) {
    Bytes body{0x03, 0x03};
    append(body, random);
    body.push_back(0x20);
    body.insert(body.end(), 32, 0x44);
    put16(body, cipher);
    body.push_back(0x00);
    put16(body, static_cast<std::uint16_t>(extensions.size()));
    append(body, extensions);
    Bytes message{0x02, static_cast<std::uint8_t>(body.size() >> 16),
                  static_cast<std::uint8_t>(body.size() >> 8),
                  static_cast<std::uint8_t>(body.size())};
    append(message, body);
    return message;
}

Bytes extension(std::uint16_t type, const Bytes& data) {
    Bytes out;
    put16(out, type);
    put16(out, static_cast<std::uint16_t>(data.size()));
    append(out, data);
    return out;
}

const Bytes kVersions = extension(0x002b, Bytes{0x03, 0x04});
Bytes x25519_share() {
    Bytes data{0x00, 0x1d, 0x00, 0x20};
    data.insert(data.end(), 32, 0x09);
    return extension(0x0033, data);
}
// SHA-256("HelloRetryRequest").
constexpr std::array<std::uint8_t, 32> kRetryRandom{
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
    0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c};
constexpr std::array<std::uint8_t, 32> kPlainRandom{0x01, 0x02, 0x03};

}  // namespace

TEST(ServerHelloProbe, ParsesTheExtensionOrderOfARawServerHello) {
    const auto share_first = mtdd::detail::parse_server_hello(
        server_hello_message(kPlainRandom, 0x1302, cat_bytes(x25519_share(), kVersions)));
    ASSERT_TRUE(share_first.has_value());
    EXPECT_FALSE(share_first->retry);
    EXPECT_EQ(share_first->cipher, 0x1302);
    EXPECT_EQ(share_first->group, 0x001d);
    EXPECT_EQ(share_first->extensions, (std::vector<std::uint16_t>{0x0033, 0x002b}));

    const auto versions_first = mtdd::detail::parse_server_hello(
        server_hello_message(kPlainRandom, 0x1301, cat_bytes(kVersions, x25519_share())));
    ASSERT_TRUE(versions_first.has_value());
    EXPECT_EQ(versions_first->extensions, kVersionsThenShare);
}

TEST(ServerHelloProbe, RejectsMalformedServerHellos) {
    const Bytes good =
        server_hello_message(kPlainRandom, 0x1301, cat_bytes(kVersions, x25519_share()));
    ASSERT_TRUE(mtdd::detail::parse_server_hello(good).has_value());
    const Bytes truncated(good.begin(), good.end() - 1);
    EXPECT_FALSE(mtdd::detail::parse_server_hello(truncated).has_value());
    Bytes trailing = good;
    trailing.push_back(0);
    EXPECT_FALSE(mtdd::detail::parse_server_hello(trailing).has_value());
    Bytes client_hello = good;
    client_hello[0] = 0x01;
    EXPECT_FALSE(mtdd::detail::parse_server_hello(client_hello).has_value());
    EXPECT_FALSE(mtdd::detail::parse_server_hello(
                     server_hello_message(kPlainRandom, 0x1301, cat_bytes(kVersions, kVersions)))
                     .has_value())
        << "a repeated extension";
    // An extension longer than the extension block.
    Bytes overrun = server_hello_message(kPlainRandom, 0x1301, extension(0x002b, Bytes(4, 0)));
    overrun[79] = 0x40;  // low byte of the first extension's length
    EXPECT_FALSE(mtdd::detail::parse_server_hello(overrun).has_value());
    EXPECT_FALSE(mtdd::detail::parse_server_hello(Bytes{}).has_value());
}

TEST(ServerHelloProbe, HelloRetryRequestIsNotTakenForTheServerHello) {
    // An HRR names the group it wants (two bytes, no key); the real ServerHello
    // follows the client's second hello.
    const Bytes retry = server_hello_message(
        kRetryRandom, 0x1302, cat_bytes(kVersions, extension(0x0033, Bytes{0x00, 0x17})));
    const auto parsed = mtdd::detail::parse_server_hello(retry);
    ASSERT_TRUE(parsed.has_value());
    EXPECT_TRUE(parsed->retry);
    EXPECT_EQ(parsed->group, 0x0017);

    mtdd::detail::ServerHelloCapture capture;
    capture.observe(retry);
    EXPECT_TRUE(capture.retried);
    EXPECT_FALSE(capture.hello.has_value()) << "an HRR alone is no ServerHello";
    Bytes final_share{0x00, 0x17, 0x00, 0x41};
    final_share.insert(final_share.end(), 65, 0x04);
    capture.observe(server_hello_message(
        kPlainRandom, 0x1302, cat_bytes(extension(0x0033, final_share), kVersions)));
    // Later handshake messages (EncryptedExtensions, ...) change nothing.
    capture.observe(Bytes{0x08, 0x00, 0x00, 0x02, 0x00, 0x00});
    ASSERT_TRUE(capture.hello.has_value());
    EXPECT_FALSE(capture.hello->retry);
    EXPECT_EQ(capture.hello->cipher, 0x1302);
    EXPECT_EQ(capture.hello->group, 0x0017);
    EXPECT_EQ(capture.hello->extensions, (std::vector<std::uint16_t>{0x0033, 0x002b}));
}

TEST(ServerHelloProbe, CapturesTheServerHelloOfADefaultOpenSslServer) {
    LocalTlsServer server;
    const auto probe =
        mtdd::detail::probe_server("127.0.0.1", server.port(), std::string(kDomain), 5s);
    ASSERT_TRUE(probe.has_value());
    EXPECT_EQ(probe->flight, server.flight_for(kDomain));
    EXPECT_EQ(probe->cipher, 0x1301) << "the client's (Chrome) order is honoured";
    EXPECT_EQ(probe->extensions, kVersionsThenShare) << "OpenSSL: 43 then 51";
    EXPECT_FALSE(probe->key_share_first);
    EXPECT_FALSE(probe->retried);
    if (openssl_offers_pq()) {
        EXPECT_EQ(probe->group, 0x11ec);
        EXPECT_EQ(probe->pq, PqAnswer::pq);
    } else {
        EXPECT_EQ(probe->group, 0x001d);
        EXPECT_EQ(probe->pq, PqAnswer::unknown);
    }
}

TEST(ServerHelloProbe, CapturesServerCipherPreferenceAndAClassicalOnlyServer) {
    LocalTlsServer server(LocalTlsServer::Mode::serve, ServerTls{kChachaFirst, true, "X25519"});
    const auto probe =
        mtdd::detail::probe_server("127.0.0.1", server.port(), std::string(kDomain), 5s);
    ASSERT_TRUE(probe.has_value());
    EXPECT_EQ(probe->cipher, 0x1303) << "server-side preference";
    EXPECT_EQ(probe->group, 0x001d);
    EXPECT_EQ(probe->pq, declined()) << "X25519 although X25519MLKEM768 was offered";
    EXPECT_FALSE(probe->retried) << "an X25519 share was offered as well";
}

TEST(ServerHelloProbe, WithoutPqTheGroupAnswerStaysUnknown) {
    LocalTlsServer server;
    const auto probe = mtdd::detail::probe_server("127.0.0.1", server.port(),
                                                  std::string(kDomain), 5s, {}, false);
    ASSERT_TRUE(probe.has_value()) << "the classical fallback still measures";
    EXPECT_EQ(probe->flight, server.flight_for(kDomain));
    EXPECT_EQ(probe->group, 0x001d);
    EXPECT_EQ(probe->pq, PqAnswer::unknown);
}

TEST(ServerHelloProbe, FollowsAHelloRetryRequestToTheFinalServerHello) {
    // P-256 is offered without a key share: the server asks for one.
    LocalTlsServer server(LocalTlsServer::Mode::serve, ServerTls{nullptr, false, "P-256"});
    const auto probe =
        mtdd::detail::probe_server("127.0.0.1", server.port(), std::string(kDomain), 5s);
    ASSERT_TRUE(probe.has_value());
    EXPECT_TRUE(probe->retried);
    EXPECT_EQ(probe->group, 0x0017) << "the final ServerHello's group";
    EXPECT_EQ(probe->extensions, kVersionsThenShare);
    EXPECT_EQ(probe->pq, declined());
    EXPECT_EQ(probe->flight, server.flight_for(kDomain)) << "the HRR is not part of the flight";
}

TEST(ServerHelloProbe, HandshakesMirrorTheMeasuredServerHello) {
    LocalTlsServer server(LocalTlsServer::Mode::serve, ServerTls{kChachaFirst, true, "X25519"});
    ProbeScope scope(server.port());
    Daemon daemon(1, false, masking_on);
    ASSERT_TRUE(daemon.services.add_user("alice", std::string(kSecretHex)));
    ASSERT_TRUE(wait_for([&] {
        return server.handshakes(kDomain) >= mtdd::detail::kServerFlightSamples;
    }, 10s));
    // The client offers 1301 and 1303 and both an X25519MLKEM768 and an
    // X25519 share; the measured server answers CHACHA20 and X25519.
    ASSERT_TRUE(wait_for([&] {
        const auto answer = daemon_answer(daemon.port(), true);
        return answer && answer->cipher == 0x1303;
    }, 5s)) << "the measured suite reaches the handshakes";
    const auto answer = daemon_answer(daemon.port(), true);
    ASSERT_TRUE(answer.has_value());
    EXPECT_EQ(answer->extensions, kVersionsThenShare);
    EXPECT_EQ(answer->group, openssl_offers_pq() ? 0x001d : 0x11ec)
        << "a declined PQ group is mirrored; an unknown answer keeps PQ";
    // Without a PQ offer: the measured suite, the X25519 answer as always.
    const auto classical = daemon_answer(daemon.port(), false);
    ASSERT_TRUE(classical.has_value());
    EXPECT_EQ(classical->cipher, 0x1303);
    EXPECT_EQ(classical->group, 0x001d);
}

TEST(ServerHelloProbe, MeasuresTheFlightOfALocalTls13Server) {
    LocalTlsServer server;
    const auto global =
        mtdd::detail::measure_server_flight("127.0.0.1", server.port(), std::string(kDomain), 5s);
    const auto front =
        mtdd::detail::measure_server_flight("127.0.0.1", server.port(), std::string(kFront), 5s);
    ASSERT_TRUE(global.has_value());
    ASSERT_TRUE(front.has_value());
    EXPECT_EQ(global, server.flight_for(kDomain));
    EXPECT_EQ(front, server.flight_for(kFront));
    EXPECT_GT(*front, *global + 500) << "40 extra subjectAltNames";
}

TEST(ServerHelloProbe, UnreachableOrNonTlsTargetsFailFast) {
    const auto start = std::chrono::steady_clock::now();
    EXPECT_FALSE(mtdd::detail::measure_server_flight("127.0.0.1", closed_port(),
                                                     std::string(kDomain), 5s));
    LocalTlsServer stalled(LocalTlsServer::Mode::stall);
    EXPECT_FALSE(mtdd::detail::measure_server_flight("127.0.0.1", stalled.port(),
                                                     std::string(kDomain), 300ms));
    std::atomic<bool> cancel{true};
    EXPECT_FALSE(mtdd::detail::measure_server_flight("127.0.0.1", stalled.port(),
                                                     std::string(kDomain), 5s,
                                                     [&] { return cancel.load(); }));
    EXPECT_LT(std::chrono::steady_clock::now() - start, 2s);
}

TEST(ServerHelloProbe, HandshakesCarryTheMeasuredLengthOfTheirUsersDomain) {
    LocalTlsServer server;
    ProbeScope scope(server.port());
    Daemon daemon(1, false, masking_on);
    ASSERT_TRUE(daemon.services.add_user("alice", std::string(kSecretHex)));
    ASSERT_TRUE(daemon.services.add_user("bob", std::string(kBobSecretHex)));
    mtdd::control::UpdateUserRequest update;
    update.name = "bob";
    update.policy.tls_domain = std::string(kFront);
    ASSERT_TRUE(daemon.services.store->update_user(update).ok());

    ASSERT_TRUE(wait_for([&] {
        return server.handshakes(kDomain) >= mtdd::detail::kServerFlightSamples &&
               server.handshakes(kFront) >= mtdd::detail::kServerFlightSamples;
    }, 10s)) << "both configured domains are probed";
    const auto global = server.flight_for(kDomain);
    const auto front = server.flight_for(kFront);
    ASSERT_TRUE(global && front);
    ASSERT_NE(*global, *front);

    EXPECT_TRUE(wait_for([&] {
        return near(app_data_length(daemon.port(), secret_bytes(), kDomain), *global);
    }, 5s)) << "alice (global tls_domain) gets " << *global;
    EXPECT_TRUE(wait_for([&] {
        return near(app_data_length(daemon.port(), bob_secret_bytes(), kFront), *front);
    }, 5s)) << "bob (personal tls_domain) gets " << *front;
    // The Ed25519 server answers with one constant length; every hello stays
    // within the jitter of it, and the jitter is used.
    std::set<std::size_t> seen;
    for (int i = 0; i < 30; ++i) {
        const auto length = app_data_length(daemon.port(), secret_bytes(), kDomain);
        ASSERT_TRUE(near(length, *global));
        seen.insert(*length);
    }
    EXPECT_GT(seen.size(), 1U) << "a measured length is jittered, not replayed exactly";
    EXPECT_EQ(scope.lookups.load(), 0U) << "the override needs no DNS";
    EXPECT_EQ(server.server_names(), (std::set<std::string>{std::string(kDomain), std::string(kFront)}));
}

TEST(ServerHelloProbe, StalledProbeBlocksNeitherHandshakesNorShutdown) {
    LocalTlsServer server(LocalTlsServer::Mode::stall);
    ProbeScope scope(server.port());
    Daemon daemon(1, false, masking_on);
    ASSERT_TRUE(daemon.services.add_user("alice", std::string(kSecretHex)));
    ASSERT_TRUE(wait_for([&] { return server.accepted() >= 1U; }, 3s)) << "probe in flight";

    for (int i = 0; i < 5; ++i) {
        const auto start = std::chrono::steady_clock::now();
        EXPECT_TRUE(in_fallback_range(app_data_length(daemon.port(), secret_bytes(), kDomain)));
        EXPECT_LT(std::chrono::steady_clock::now() - start, 500ms) << "reactor waited for the probe";
    }
    const auto start = std::chrono::steady_clock::now();
    daemon.stop();
    EXPECT_LT(std::chrono::steady_clock::now() - start, 1500ms) << "shutdown waited for the probe";
}

TEST(ServerHelloProbe, UnreachableDomainFallsBackToARandomLength) {
    ProbeScope scope(closed_port());
    Daemon daemon(1, false, masking_on);
    ASSERT_TRUE(daemon.services.add_user("alice", std::string(kSecretHex)));
    std::this_thread::sleep_for(300ms);  // the first probe has failed by now

    std::set<std::size_t> seen;
    for (int i = 0; i < 20; ++i) {
        const auto start = std::chrono::steady_clock::now();
        const auto length = app_data_length(daemon.port(), secret_bytes(), kDomain);
        EXPECT_LT(std::chrono::steady_clock::now() - start, 500ms);
        ASSERT_TRUE(in_fallback_range(length));
        seen.insert(*length);
    }
    EXPECT_GT(seen.size(), 1U) << "the fallback is a distribution, not a constant";
}

// ---------------------------------------------------------------------------
// Server processing time (server_hello_delay_auto): the probe measures how
// long the real server takes before its ServerHello, and FakeTLS handshakes
// of that domain are then held for a draw from the measured spread.
// ---------------------------------------------------------------------------

namespace {

using AutoClock = std::chrono::steady_clock;

// One authenticated FakeTLS hello: the time from the hello written to the
// first byte of the answer, which must be ServerHello, one CCS and one
// ApplicationData record (the shape the Telegram client accepts).
std::optional<AutoClock::duration> auto_hello_latency(std::uint16_t port) {
    const int fd = connect_loopback(port);
    if (fd < 0) return std::nullopt;
    const auto ts = static_cast<std::uint32_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch())
            .count());
    static std::atomic<unsigned> variant{200};
    const auto hello =
        make_client_hello(secret_bytes(), ts, kDomain, static_cast<std::uint8_t>(variant.fetch_add(1)));
    std::optional<AutoClock::duration> first;
    bool shaped = send_all(fd, hello);
    const auto sent = AutoClock::now();
    for (const std::uint8_t type : {std::uint8_t{0x16}, std::uint8_t{0x14}, std::uint8_t{0x17}}) {
        if (!shaped) break;
        std::array<std::uint8_t, 5> header{};
        shaped = recv_exact(fd, header.data(), header.size(), 3000) && header[0] == type;
        if (!first) first = AutoClock::now() - sent;
        Bytes body((static_cast<std::size_t>(header[3]) << 8) | header[4]);
        if (shaped && !body.empty()) shaped = recv_exact(fd, body.data(), body.size(), 3000);
    }
    ::close(fd);
    if (!shaped) return std::nullopt;
    return first;
}

std::uint64_t auto_delays(const mtdd::control::Statistics& stats) {
    std::uint64_t total = 0;
    for (const auto& [bucket, count] : stats.snapshot().server_hello_auto_delay_total) {
        total += count;
    }
    return total;
}

// The per-domain processing-time gauge appears once a probe succeeded.
bool processing_measured(const mtdd::control::Statistics& stats) {
    return stats.prometheus_text().find("mtdd_masking_server_processing_samples{domain=\"" +
                                        std::string(kDomain) + "\"}") != std::string::npos;
}

void masking_auto(mtdd::Config& config) {
    config.masking = true;
    config.server_hello_delay_auto = true;
}

}  // namespace

TEST(ServerHelloProbe, MeasuresTheServersProcessingTime) {
    ServerTls tls;
    tls.processing = 40ms;
    LocalTlsServer server(LocalTlsServer::Mode::serve, tls);
    const auto probe =
        mtdd::detail::probe_server("127.0.0.1", server.port(), std::string(kDomain), 5s);
    ASSERT_TRUE(probe.has_value());
    ASSERT_TRUE(probe->hello_latency.has_value());
    ASSERT_TRUE(probe->processing.has_value());
    EXPECT_GE(*probe->hello_latency, 40ms) << "the server slept before its ServerHello";
    EXPECT_LT(probe->connect_rtt, 40ms) << "loopback connect";
    EXPECT_EQ(*probe->processing, *probe->hello_latency - probe->connect_rtt);
    EXPECT_GE(*probe->processing, 39ms);
    EXPECT_LT(*probe->processing, 2s);

    // After a HelloRetryRequest the answer to the second ClientHello is the
    // one timed; it is still a measurement.
    ServerTls retry{nullptr, false, "P-256", 40ms};
    LocalTlsServer retrying(LocalTlsServer::Mode::serve, retry);
    const auto retried =
        mtdd::detail::probe_server("127.0.0.1", retrying.port(), std::string(kDomain), 5s);
    ASSERT_TRUE(retried.has_value());
    EXPECT_TRUE(retried->retried);
    ASSERT_TRUE(retried->processing.has_value());
    EXPECT_GE(retried->processing->count(), 0);
}

TEST(ServerHelloAutoDelay, MeasuredDomainHoldsTheHelloForItsProcessingTime) {
    ServerTls tls;
    tls.processing = 30ms;
    LocalTlsServer server(LocalTlsServer::Mode::serve, tls);
    ProbeScope scope(server.port());
    Daemon daemon(1, false, masking_auto);
    ASSERT_TRUE(daemon.services.add_user("alice", std::string(kSecretHex)));
    ASSERT_TRUE(wait_for([&] { return processing_measured(daemon.services.stats); }, 10s));

    const auto text = daemon.services.stats.prometheus_text();
    const std::string median = "mtdd_masking_server_processing_us{domain=\"" +
                               std::string(kDomain) + "\",quantile=\"0.5\"} ";
    const auto at = text.find(median);
    ASSERT_NE(at, std::string::npos) << text;
    EXPECT_GE(std::stoull(text.substr(at + median.size())), 29000U);

    for (int i = 0; i < 4; ++i) {
        const auto latency = auto_hello_latency(daemon.port());
        ASSERT_TRUE(latency.has_value()) << "one ServerHello, one CCS, one ApplicationData";
        EXPECT_GE(*latency, 29ms) << "held for the measured processing time";
        EXPECT_LT(*latency, 1s);
    }
    const auto snapshot = daemon.services.stats.snapshot();
    EXPECT_EQ(auto_delays(daemon.services.stats), 4U);
    EXPECT_EQ(snapshot.server_hello_auto_delay_total.at("le_50ms"), 4U);
    EXPECT_GE(snapshot.server_hello_auto_delay_us_total, 4U * 29000U);
}

TEST(ServerHelloAutoDelay, UnmeasuredDomainAnswersAtOnce) {
    ProbeScope scope(closed_port());
    Daemon daemon(1, false, masking_auto);
    ASSERT_TRUE(daemon.services.add_user("alice", std::string(kSecretHex)));
    std::this_thread::sleep_for(300ms);  // the first probe has failed by now
    std::vector<AutoClock::duration> latencies;
    for (int i = 0; i < 5; ++i) {
        const auto latency = auto_hello_latency(daemon.port());
        ASSERT_TRUE(latency.has_value());
        latencies.push_back(*latency);
    }
    EXPECT_LT(*std::min_element(latencies.begin(), latencies.end()), 100ms);
    EXPECT_EQ(auto_delays(daemon.services.stats), 0U) << "no measurement, no automatic delay";
    EXPECT_FALSE(processing_measured(daemon.services.stats));
}

TEST(ServerHelloAutoDelay, ManualBoundsAndDisablingOverrideTheMeasurement) {
    ServerTls tls;
    tls.processing = 30ms;
    LocalTlsServer server(LocalTlsServer::Mode::serve, tls);
    ProbeScope scope(server.port());
    {
        Daemon daemon(1, false, [](mtdd::Config& config) {
            masking_auto(config);
            config.server_hello_delay_min = 200ms;
            config.server_hello_delay_max = 200ms;
        });
        ASSERT_TRUE(daemon.services.add_user("alice", std::string(kSecretHex)));
        ASSERT_TRUE(wait_for([&] { return processing_measured(daemon.services.stats); }, 10s));
        const auto latency = auto_hello_latency(daemon.port());
        ASSERT_TRUE(latency.has_value());
        EXPECT_GE(*latency, 200ms) << "the manual delay, not the measured 30 ms";
        EXPECT_EQ(auto_delays(daemon.services.stats), 0U);
    }
    {
        Daemon daemon(1, false, [](mtdd::Config& config) {
            config.masking = true;
            config.server_hello_delay_auto = false;
        });
        ASSERT_TRUE(daemon.services.add_user("alice", std::string(kSecretHex)));
        ASSERT_TRUE(wait_for([&] { return processing_measured(daemon.services.stats); }, 10s))
            << "still measured and exported";
        std::vector<AutoClock::duration> latencies;
        for (int i = 0; i < 4; ++i) {
            const auto latency = auto_hello_latency(daemon.port());
            ASSERT_TRUE(latency.has_value());
            latencies.push_back(*latency);
        }
        EXPECT_LT(*std::min_element(latencies.begin(), latencies.end()), 25ms)
            << "disabled: answered at once";
        EXPECT_EQ(auto_delays(daemon.services.stats), 0U);
    }
}

TEST(ServerHelloAutoDelay, SlowServerIsCappedAndAResetDuringTheDelayIsClean) {
    ServerTls tls;
    tls.processing = 250ms;
    LocalTlsServer server(LocalTlsServer::Mode::serve, tls);
    ProbeScope scope(server.port());
    testing::internal::CaptureStderr();
    {
        Daemon daemon(1, false, [](mtdd::Config& config) {
            masking_auto(config);
            config.watch_ips = {"127.0.0.1"};
        });
        ASSERT_TRUE(daemon.services.add_user("alice", std::string(kSecretHex)));
        ASSERT_TRUE(wait_for([&] { return processing_measured(daemon.services.stats); }, 15s));

        // Every sample is above the cap: exactly 100 ms, not 250.
        std::vector<AutoClock::duration> latencies;
        for (int i = 0; i < 3; ++i) {
            const auto latency = auto_hello_latency(daemon.port());
            ASSERT_TRUE(latency.has_value());
            EXPECT_GE(*latency, 100ms);
            latencies.push_back(*latency);
        }
        EXPECT_LT(*std::min_element(latencies.begin(), latencies.end()), 240ms)
            << "capped below the measured 250 ms";
        EXPECT_EQ(daemon.services.stats.snapshot().server_hello_auto_delay_total.at("le_100ms"),
                  3U);

        // A client that resets during the automatic delay: closed at once,
        // counted as a failed handshake, and the dropped deadline fires for
        // nothing. The probing clients above are closed (and counted) first.
        ASSERT_TRUE(wait_for([&] {
            return daemon.services.stats.snapshot().connections_active == 0;
        }, 2s));
        const auto failures = stat_counter(daemon.services.stats, "handshakes", "failure");
        const int fd = connect_loopback(daemon.port());
        ASSERT_GE(fd, 0);
        const auto ts = static_cast<std::uint32_t>(
            std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch())
                .count());
        ASSERT_TRUE(send_all(fd, make_client_hello(secret_bytes(), ts, kDomain, 250)));
        const auto held_until = AutoClock::now() + 2s;
        bool held = false;
        while (!held && AutoClock::now() < held_until) {
            const auto snapshot = daemon.services.stats.snapshot();
            const auto user = snapshot.users.find("alice");
            held = user != snapshot.users.end() && user->second.active_connections == 1U;
            if (!held) std::this_thread::sleep_for(1ms);
        }
        ASSERT_TRUE(held) << "authenticated";
        int pending = 0;
        ASSERT_EQ(::ioctl(fd, FIONREAD, &pending), 0);
        EXPECT_EQ(pending, 0) << "the hello is still held";
        linger option{1, 0};
        ::setsockopt(fd, SOL_SOCKET, SO_LINGER, &option, sizeof(option));
        ::close(fd);
        ASSERT_TRUE(wait_for([&] {
            return daemon.services.stats.snapshot().connections_active == 0;
        }, 2s));
        EXPECT_TRUE(wait_for([&] {
            return stat_counter(daemon.services.stats, "handshakes", "failure") == failures + 1;
        }, 1s));
        std::this_thread::sleep_for(150ms);  // past the dropped deadline
        const auto after = auto_hello_latency(daemon.port());
        ASSERT_TRUE(after.has_value()) << "the reactor still serves normally";
        EXPECT_GE(*after, 100ms);

        // Shutdown during the automatic delay closes the held client too.
        const int held_fd = connect_loopback(daemon.port());
        ASSERT_GE(held_fd, 0);
        ASSERT_TRUE(send_all(held_fd, make_client_hello(secret_bytes(), ts, kDomain, 251)));
        ASSERT_TRUE(wait_for([&] {
            const auto snapshot = daemon.services.stats.snapshot();
            const auto user = snapshot.users.find("alice");
            return user != snapshot.users.end() && user->second.active_connections == 1U;
        }, 2s));
        daemon.stop();
        EXPECT_TRUE(wait_closed(held_fd, 1000));
        ::close(held_fd);
    }
    const std::string log = testing::internal::GetCapturedStderr();
    EXPECT_NE(log.find(" server_hello delay_us=100000 auto=1"), std::string::npos) << log;
}
