#include "../support/control_fixture.hpp"

#include "../../src/control/http_internal.hpp"

namespace {

constexpr const char* kReadToken = "unit-test-read-token-not-a-secret";
constexpr const char* kMetricsToken = "unit-test-metrics-token-not-a-secret";

using mtdd::control::HttpRole;

HttpOptions read_options() {
  HttpOptions options;
  options.read_token = kReadToken;
  options.public_host = "203.0.113.7";
  options.public_port = 443;
  options.tls_domain = "example.org";
  return options;
}

TEST(HttpScopeTest, ReadTokenCanOnlyObserve) {
  Harness h(StoreOptions{}, read_options());
  ASSERT_EQ(h.req("POST", "/v1/users", make_user_body("alice", std::string(kHexA))).status, 201);

  for (const char* route : {"/v1/health", "/v1/status", "/v1/users", "/v1/users/alice"}) {
    EXPECT_EQ(h.req("GET", route, {}, kReadToken).status, 200) << route;
  }
  const auto list = h.req("GET", "/v1/users", {}, kReadToken);
  EXPECT_EQ(list.body.find(kHexA), std::string::npos);

  const auto links = h.req("GET", "/v1/users/alice/links", {}, kReadToken);
  EXPECT_EQ(links.status, 403);
  EXPECT_EQ(parse_json(links)["error"]["type"], "forbidden_scope");
  EXPECT_EQ(links.body.find(kHexA), std::string::npos);
  EXPECT_EQ(h.req("GET", "/metrics", {}, kReadToken).status, 403);

  EXPECT_EQ(h.req("POST", "/v1/users", make_user_body("bob"), kReadToken).status, 403);
  EXPECT_EQ(h.req("PATCH", "/v1/users/alice", R"({"enabled":false})", kReadToken).status, 403);
  EXPECT_EQ(h.req("POST", "/v1/users/alice/rotate-secret", "{}", kReadToken).status, 403);
  EXPECT_EQ(h.req("DELETE", "/v1/users/alice", {}, kReadToken).status, 403);

  const auto snapshot = h.store().snapshot();
  ASSERT_EQ(snapshot->users.size(), 1u);
  EXPECT_TRUE(snapshot->users.front().enabled);
  EXPECT_EQ(snapshot->users.front().secret_hex, kHexA);
}

TEST(HttpScopeTest, UnknownRouteStillAuthenticatesFirst) {
  Harness h(StoreOptions{}, read_options());
  EXPECT_EQ(h.req("GET", "/v1/nope", {}, "").status, 401);
  EXPECT_EQ(h.req("GET", "/v1/nope", {}, kReadToken).status, 404);
}

TEST(HttpScopeTest, AdminKeepsLegacyMetricsWithDeprecation) {
  Harness h(StoreOptions{}, read_options());
  const auto metrics = h.req("GET", "/metrics");
  ASSERT_EQ(metrics.status, 200);
  EXPECT_EQ(header_value(metrics, "deprecation"), "true");
  EXPECT_NE(metrics.body.find("mtdd_"), std::string::npos);
}

TEST(HttpScopeTest, StartRejectsBadTokenConfiguration) {
  TempDir dir;
  auto store = open_store_or_throw(dir.file("users.json"));
  Statistics stats;

  HttpOptions same;
  same.bearer_token = kToken;
  same.read_token = kToken;
  EXPECT_FALSE(ControlServer(store, stats, same).start().ok());

  HttpOptions spaced;
  spaced.bearer_token = kToken;
  spaced.read_token = "has space";
  EXPECT_FALSE(ControlServer(store, stats, spaced).start().ok());

  HttpOptions open_metrics;
  open_metrics.role = HttpRole::metrics;
  EXPECT_FALSE(ControlServer(store, stats, open_metrics).start().ok());

  HttpOptions bad_cidr;
  bad_cidr.bearer_token = kToken;
  bad_cidr.allow_networks = {"127.0.0.0/33"};
  EXPECT_FALSE(ControlServer(store, stats, bad_cidr).start().ok());
}

class MetricsListener {
 public:
  explicit MetricsListener(HttpOptions options)
      : store_(open_store_or_throw(dir_.file("users.json"))) {
    options.role = HttpRole::metrics;
    server_ = std::make_unique<ControlServer>(store_, stats_, std::move(options));
    auto started = server_->start();
    if (!started.ok()) throw std::runtime_error(started.error().message);
    port_ = started.value();
  }
  ~MetricsListener() { server_->stop(); }

  HttpResult get(const std::string& path, const std::string& token) {
    return http_call(port_, "GET", path, token);
  }

 private:
  TempDir dir_;
  Statistics stats_;
  UserStore store_;
  std::unique_ptr<ControlServer> server_;
  uint16_t port_{0};
};

TEST(MetricsListenerTest, TokenProtectedExporterServesOnlyMetrics) {
  HttpOptions options;
  options.metrics_token = kMetricsToken;
  options.bearer_token = kToken;  // ignored by the metrics role
  MetricsListener m(options);

  const auto ok = m.get("/metrics", kMetricsToken);
  ASSERT_EQ(ok.status, 200);
  EXPECT_NE(header_value(ok, "content-type").find("text/plain"), std::string::npos);
  EXPECT_TRUE(header_value(ok, "deprecation").empty());

  EXPECT_EQ(m.get("/metrics", "").status, 401);
  EXPECT_EQ(m.get("/metrics", kToken).status, 401);
  EXPECT_EQ(m.get("/v1/users", kMetricsToken).status, 404);
  EXPECT_EQ(m.get("/v1/health", kMetricsToken).status, 404);
}

TEST(MetricsListenerTest, AllowlistOnlyExporter) {
  HttpOptions loopback;
  loopback.allow_networks = {"127.0.0.0/8", "::1"};
  MetricsListener open(loopback);
  EXPECT_EQ(open.get("/metrics", "").status, 200);

  HttpOptions remote_only;
  remote_only.allow_networks = {"10.0.0.0/8"};
  MetricsListener closed(remote_only);
  const auto refused = closed.get("/metrics", "");
  EXPECT_EQ(refused.status, 403);
  EXPECT_EQ(parse_json(refused)["error"]["type"], "forbidden");
}

TEST(HttpAllowlistTest, ApiRefusesPeersOutsideAllowlist) {
  HttpOptions options;
  options.allow_networks = {"192.0.2.0/24", "2001:db8::/32"};
  Harness h(StoreOptions{}, options);
  EXPECT_EQ(h.req("GET", "/v1/health").status, 403);

  HttpOptions host;
  host.allow_networks = {"127.0.0.1"};
  Harness allowed(StoreOptions{}, host);
  EXPECT_EQ(allowed.req("GET", "/v1/health").status, 200);
}

TEST(IpNetworkTest, ParsesAndRejects) {
  using mtdd::control::detail::parse_ip_network;
  ASSERT_TRUE(parse_ip_network("10.0.0.0/8"));
  EXPECT_EQ(parse_ip_network("10.0.0.0/8")->prefix, 104);
  EXPECT_EQ(parse_ip_network("127.0.0.1")->prefix, 128);
  EXPECT_EQ(parse_ip_network("fd00::/8")->prefix, 8);
  for (const char* bad : {"", "10.0.0.0/", "10.0.0.0/33", "::/129", "10.0.0.0/8x",
                          "example.org", "10.0.0.0/-1", "1.2.3.4/0008"}) {
    EXPECT_FALSE(parse_ip_network(bad)) << bad;
  }
}

}  // namespace
