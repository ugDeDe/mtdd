#include "mtdd/metadata.hpp"

#include <arpa/inet.h>
#include <algorithm>
#include <cerrno>
#include <charconv>
#include <condition_variable>
#include <curl/curl.h>
#include <fcntl.h>
#include <mutex>
#include <set>
#include <sstream>
#include <stdexcept>
#include <tuple>
#include <sys/stat.h>
#include <unistd.h>

namespace mtdd {
namespace {
constexpr std::size_t metadata_limit{1024 * 1024};

std::string read_file(const std::filesystem::path& path) {
    struct Fd {
        int value;
        ~Fd() { if (value >= 0) ::close(value); }
    } file{::open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NONBLOCK | O_NOFOLLOW)};
    if (file.value < 0) throw std::runtime_error("cannot open ME metadata file");
    struct stat info{};
    if (::fstat(file.value, &info) != 0 || !S_ISREG(info.st_mode))
        throw std::runtime_error("ME metadata must be a regular, non-symlink file");
    std::string result;
    std::array<char, 4096> buffer{};
    while (true) {
        const auto size = ::read(file.value, buffer.data(), buffer.size());
        if (size == 0) break;
        if (size < 0) {
            if (errno == EINTR) continue;
            throw std::runtime_error("cannot read ME metadata file");
        }
        result.append(buffer.data(), static_cast<std::size_t>(size));
        if (result.size() > metadata_limit) throw std::runtime_error("ME metadata exceeds size limit");
    }
    return result;
}

size_t receive_body(char* data, size_t size, size_t count, void* opaque) noexcept {
    if (size != 0 && count > metadata_limit / size) return 0;
    const auto bytes = size * count;
    auto& body = *static_cast<std::string*>(opaque);
    if (bytes > metadata_limit - body.size()) return 0;
    try { body.append(data, bytes); } catch (...) { return 0; }
    return bytes;
}

struct CurlGlobal {
    CurlGlobal() {
        if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK) throw std::runtime_error("curl initialization failed");
    }
    ~CurlGlobal() { curl_global_cleanup(); }
};

int transfer_progress(void* opaque, curl_off_t, curl_off_t, curl_off_t, curl_off_t) noexcept {
    return static_cast<std::stop_token*>(opaque)->stop_requested() ? 1 : 0;
}

// `upstream` (nullptr: plain) is how the request leaves the host, the same
// way as the Telegram connections (Config::upstreams, default scope).
std::string download(const char* url, std::stop_token stop, std::chrono::seconds shutdown_budget,
                     const UpstreamConfig* upstream) {
    static const CurlGlobal curl_global;
    (void)curl_global;
    struct CurlDeleter { void operator()(CURL* curl) const noexcept { curl_easy_cleanup(curl); } };
    std::unique_ptr<CURL, CurlDeleter> curl(curl_easy_init());
    if (!curl) throw std::runtime_error("cannot initialize metadata HTTP client");
    std::string body;
    const auto option = [&](CURLoption key, auto value) {
        if (curl_easy_setopt(curl.get(), key, value) != CURLE_OK)
            throw std::runtime_error("cannot configure metadata HTTP client");
    };
    const auto timeout_ms = std::clamp(static_cast<long>(shutdown_budget.count() * 1000), 1000L, 15000L);
    option(CURLOPT_URL, url);
    option(CURLOPT_PROTOCOLS_STR, "https");
    option(CURLOPT_FOLLOWLOCATION, 0L);
    option(CURLOPT_CONNECTTIMEOUT_MS, std::min(5000L, timeout_ms));
    option(CURLOPT_TIMEOUT_MS, timeout_ms);
    option(CURLOPT_NOSIGNAL, 1L);
    option(CURLOPT_WRITEFUNCTION, receive_body);
    option(CURLOPT_WRITEDATA, &body);
    option(CURLOPT_USERAGENT, "mtdd/0.1");
    option(CURLOPT_NOPROGRESS, 0L);
    option(CURLOPT_XFERINFOFUNCTION, transfer_progress);
    option(CURLOPT_XFERINFODATA, &stop);
    std::string proxy;
    std::string interface;
    if (upstream != nullptr) {
        if (!upstream->interface.empty()) {
            interface = "if!" + upstream->interface;
        } else if (!upstream->bind_address.empty()) {
            interface = "host!" + upstream->bind_address;
        }
        if (!interface.empty()) option(CURLOPT_INTERFACE, interface.c_str());
        if (upstream->type == UpstreamConfig::Type::socks5) {
            // socks5h: the proxy resolves core.telegram.org.
            proxy = upstream->host.find(':') == std::string::npos
                        ? "socks5h://" + upstream->host + ":" + std::to_string(upstream->port)
                        : "socks5h://[" + upstream->host + "]:" + std::to_string(upstream->port);
            option(CURLOPT_PROXY, proxy.c_str());
            if (!upstream->username.empty()) {
                option(CURLOPT_PROXYUSERNAME, upstream->username.c_str());
                option(CURLOPT_PROXYPASSWORD, upstream->password.c_str());
            }
        }
    }
    if (stop.stop_requested()) throw std::runtime_error("metadata refresh stopped");
    if (curl_easy_perform(curl.get()) != CURLE_OK) throw std::runtime_error("ME metadata download failed");
    long status{};
    curl_easy_getinfo(curl.get(), CURLINFO_RESPONSE_CODE, &status);
    if (status != 200) throw std::runtime_error("ME metadata server returned non-success status");
    return body;
}

template <typename T> T integer(std::string_view text) {
    T value{};
    const auto [end, error] = std::from_chars(text.data(), text.data() + text.size(), value);
    if (error != std::errc{} || end != text.data() + text.size()) throw std::invalid_argument("invalid ME configuration integer");
    return value;
}

MeEndpoint endpoint(std::int16_t dc, const std::string& value) {
    MeEndpoint result{dc, {}, 0};
    std::string_view port;
    if (!value.empty() && value.front() == '[') {
        const auto close = value.find(']');
        if (close == std::string::npos || close + 2 >= value.size() || value[close + 1] != ':')
            throw std::invalid_argument("invalid ME IPv6 endpoint");
        result.host = value.substr(1, close - 1);
        port = std::string_view(value).substr(close + 2);
    } else {
        const auto colon = value.find(':');
        if (colon == std::string::npos) throw std::invalid_argument("invalid ME IPv4 endpoint");
        result.host = value.substr(0, colon);
        port = std::string_view(value).substr(colon + 1);
    }
    result.port = integer<std::uint16_t>(port);
    std::array<unsigned char, 16> bytes{};
    if (result.port == 0 || (inet_pton(AF_INET, result.host.c_str(), bytes.data()) != 1 &&
                             inet_pton(AF_INET6, result.host.c_str(), bytes.data()) != 1))
        throw std::invalid_argument("invalid numeric ME endpoint");
    return result;
}
} // namespace

std::vector<MeEndpoint> parse_me_config(std::string_view text) {
    if (text.size() > metadata_limit) throw std::invalid_argument("ME config exceeds size limit");
    std::string clean;
    std::istringstream lines{std::string(text)};
    for (std::string line; std::getline(lines, line);) {
        const auto comment = line.find('#');
        clean.append(line, 0, comment);
        clean.push_back('\n');
    }
    std::istringstream statements{clean};
    std::vector<MeEndpoint> result;
    std::set<std::tuple<std::int16_t, std::string, std::uint16_t>> seen;
    for (std::string statement; std::getline(statements, statement, ';');) {
        std::istringstream fields{statement};
        std::string directive;
        if (!(fields >> directive)) continue;
        std::string dc_text, address, extra;
        if (!(fields >> dc_text)) throw std::invalid_argument("missing ME datacenter");
        const auto dc = integer<std::int16_t>(dc_text);
        if (dc == 0 || dc < -1000 || dc > 1000) throw std::invalid_argument("unsupported ME datacenter");
        if (directive == "default") {
            if (fields >> extra) throw std::invalid_argument("unexpected ME default fields");
            continue;
        }
        if (directive != "proxy_for" || !(fields >> address) || (fields >> extra))
            throw std::invalid_argument("unexpected ME configuration directive");
        auto route = endpoint(dc, address);
        if (seen.emplace(route.dc, route.host, route.port).second) result.push_back(std::move(route));
        if (result.size() > 512) throw std::invalid_argument("too many ME endpoints");
    }
    if (result.empty()) throw std::invalid_argument("ME configuration contains no endpoints");
    return result;
}

// Tries the default-scope upstreams by descending weight until one answers;
// plain when no upstreams are configured.
static std::string fetch_metadata(const Config& config, const char* url, std::stop_token stop) {
    std::vector<const UpstreamConfig*> order;
    for (const auto& upstream : config.upstreams) {
        if (upstream.scopes.empty()) order.push_back(&upstream);
    }
    std::stable_sort(order.begin(), order.end(),
                     [](const UpstreamConfig* a, const UpstreamConfig* b) { return a->weight > b->weight; });
    if (order.empty()) return download(url, stop, config.shutdown_timeout, nullptr);
    for (std::size_t i = 0; i < order.size(); ++i) {
        try {
            return download(url, stop, config.shutdown_timeout, order[i]);
        } catch (const std::runtime_error&) {
            if (i + 1 == order.size() || stop.stop_requested()) throw;
        }
    }
    throw std::runtime_error("ME metadata download failed");
}

MeMetadata load_me_metadata(const Config& config, std::stop_token stop) {
    if (stop.stop_requested()) throw std::runtime_error("metadata refresh stopped");
    const auto config_text = config.me_config_path.empty() ? fetch_metadata(config, "https://core.telegram.org/getProxyConfig", stop) : read_file(config.me_config_path);
    if (stop.stop_requested()) throw std::runtime_error("metadata refresh stopped");
    const auto secret_text = config.me_secret_path.empty() ? fetch_metadata(config, "https://core.telegram.org/getProxySecret", stop) : read_file(config.me_secret_path);
    if (secret_text.size() != 128) throw std::invalid_argument("ME secret must contain exactly 128 binary bytes");
    MeMetadata result;
    result.endpoints = parse_me_config(config_text);
    result.secret.assign(secret_text.begin(), secret_text.end());
    return result;
}

MetadataProvider::MetadataProvider(Config config) : config_(std::move(config)) {
    thread_ = std::jthread([this](std::stop_token stop) { run(stop); });
}

MetadataProvider::~MetadataProvider() {
    thread_.request_stop();
    if (thread_.joinable()) thread_.join();
}

std::shared_ptr<const MeMetadata> MetadataProvider::snapshot() const noexcept { return current_.load(); }
std::uint64_t MetadataProvider::failures() const noexcept { return failures_.load(std::memory_order_relaxed); }

void MetadataProvider::run(std::stop_token stop) {
    std::mutex mutex;
    std::condition_variable_any wake;
    while (!stop.stop_requested()) {
        bool success{};
        try {
            auto next = std::make_shared<MeMetadata>(load_me_metadata(config_, stop));
            const auto previous = current_.load();
            if (!previous || previous->endpoints != next->endpoints || previous->secret != next->secret) {
                next->generation = previous ? previous->generation + 1 : 1;
                current_.store(std::move(next));
            }
            success = true;
        } catch (const std::exception&) {
            failures_.fetch_add(1, std::memory_order_relaxed);
        }
        std::unique_lock lock{mutex};
        wake.wait_for(lock, stop, success ? config_.metadata_refresh : std::chrono::seconds(10), [] { return false; });
    }
}
} // namespace mtdd
