#include "../support/control_fixture.hpp"

namespace {

TEST(HttpAuthTest, AllRoutesRequireBearerTokenAndDoNotMutate) {
  Harness h;
  const std::vector<std::string> routes = {
      "/v1/health", "/v1/ready", "/v1/status", "/v1/users",
      "/v1/users/alice", "/v1/users/alice/links", "/metrics"};
  for (const auto& route : routes) {
    auto missing = h.req("GET", route, {}, "");
    EXPECT_EQ(missing.status, 401) << route;
    EXPECT_NE(header_value(missing, "www-authenticate").find("Bearer"),
              std::string::npos);
    auto wrong = h.req("GET", route, {}, "wrong-token");
    EXPECT_EQ(wrong.status, 401) << route;
  }
  auto post_missing = h.req("POST", "/v1/users", R"({"name":"alice"})", "");
  EXPECT_EQ(post_missing.status, 401);
  auto post_wrong = h.req("POST", "/v1/users", R"({"name":"alice"})", "nope");
  EXPECT_EQ(post_wrong.status, 401);

  auto list = h.req("GET", "/v1/users");
  ASSERT_EQ(list.status, 200);
  auto j = parse_json(list);
  EXPECT_EQ(j["data"]["revision"], 0);
  EXPECT_TRUE(j["data"]["users"].empty());
  EXPECT_EQ(h.store().snapshot()->revision, 0u);
}

TEST(HttpLinksTest, ReturnsProtectedLinksAndTracksRotations) {
  HttpOptions options;
  options.public_host = "2001:db8::1";
  options.public_port = 8443;
  options.tls_domain = "example.org";
  Harness h(StoreOptions{}, options);
  auto created = h.req("POST", "/v1/users", R"({"name":"alice","secret":"00112233445566778899aabbccddeeff"})");
  ASSERT_EQ(created.status, 201) << created.body;
  auto response = h.req("GET", "/v1/users/alice/links");
  ASSERT_EQ(response.status, 200) << response.body;
  EXPECT_EQ(header_value(response, "cache-control"), "no-store");
  const auto data = parse_json(response)["data"];
  EXPECT_EQ(data["links"]["telegram"], "https://t.me/proxy?server=2001%3Adb8%3A%3A1&port=8443&secret=ee00112233445566778899aabbccddeeff6578616d706c652e6f7267");
  EXPECT_EQ(data["links"]["native"], "tg://proxy?server=2001%3Adb8%3A%3A1&port=8443&secret=ee00112233445566778899aabbccddeeff6578616d706c652e6f7267");
  EXPECT_EQ(h.req("GET", "/v1/users/missing/links").status, 404);
  EXPECT_EQ(h.req("POST", "/v1/users/alice/links").status, 405);
  ASSERT_EQ(h.req("POST", "/v1/users/alice/rotate-secret", R"({"secret":"ffeeddccbbaa99887766554433221100"})").status, 200);
  EXPECT_NE(h.req("GET", "/v1/users/alice/links").body.find("eeffeeddccbbaa99887766554433221100"), std::string::npos);
  EXPECT_EQ(h.req("GET", "/v1/users").body.find("ffeeddccbbaa99887766554433221100"), std::string::npos);
  ASSERT_EQ(h.req("PATCH", "/v1/users/alice", R"({"enabled":false})").status, 200);
  EXPECT_FALSE(parse_json(h.req("GET", "/v1/users/alice/links"))["data"]["enabled"].get<bool>());
}

TEST(HttpLinksTest, RequiresConfiguredPublicAddress) {
  Harness h;
  ASSERT_EQ(h.req("POST", "/v1/users", R"({"name":"alice"})").status, 201);
  EXPECT_EQ(h.req("GET", "/v1/users/alice/links").status, 503);
}

TEST(HttpHealthTest, HealthAndReadiness) {
  Harness h;
  auto health = h.req("GET", "/v1/health");
  ASSERT_EQ(health.status, 200);
  auto health_json = parse_json(health);
  EXPECT_EQ(health_json["data"]["status"], "ok");
  EXPECT_EQ(health_json["data"]["revision"], 0);

  auto ready_initial = h.req("GET", "/v1/ready");
  EXPECT_EQ(ready_initial.status, 503);
  EXPECT_EQ(parse_json(ready_initial)["data"]["ready"], false);

  h.stats().set_ready(true);
  auto ready = h.req("GET", "/v1/ready");
  EXPECT_EQ(ready.status, 200);
  EXPECT_EQ(parse_json(ready)["data"]["ready"], true);
}

TEST(HttpStatusTest, StatusReportsActualRuntimeStatistics) {
  Harness h;
  h.stats().set_ready(true);
  h.stats().set_build_info("9.9.9");
  h.stats().connection_accepted();
  h.stats().connection_accepted();
  h.stats().connection_closed();
  h.stats().connection_rejected(RejectReason::overload);
  h.stats().handshake(HandshakeResult::success);
  auto alice = h.stats().user("alice");
  ASSERT_NE(alice, nullptr);
  alice->connection_opened();
  alice->add_payload(Direction::client_to_server, 11);
  alice->add_payload(Direction::server_to_client, 22);
  alice->set_active_unique_ips(2);
  alice->set_qualified_unique_ips(1);
  h.stats().set_active_unique_ips(4);
  h.stats().set_qualified_unique_ips(3);
  h.stats().me_connected(3, true);
  h.stats().me_pending_buffer_bytes(4096);

  CreateUserRequest request;
  request.name = "alice";
  ASSERT_TRUE(h.store().create_user(request).ok());

  auto response = h.req("GET", "/v1/status");
  ASSERT_EQ(response.status, 200);
  auto data = parse_json(response)["data"];
  EXPECT_TRUE(data["ready"].get<bool>());
  EXPECT_EQ(data["revision"], 1);
  EXPECT_EQ(data["users_total"], 1);
  EXPECT_EQ(data["users_enabled"], 1);
  EXPECT_TRUE(data["uptime_seconds"].is_number_unsigned());
  EXPECT_EQ(data["connections_active"], 1);
  EXPECT_EQ(data["unique_ips_active"], 3);
  EXPECT_EQ(data["unique_ips_seen"], 4);
  EXPECT_EQ(data["connections_accepted_total"], 2);
  EXPECT_EQ(data["connections_rejected_total"], 1);
  EXPECT_EQ(data["handshakes_total"], 1);
  EXPECT_EQ(data["build"]["version"], "9.9.9");
  EXPECT_EQ(data["me"]["connected_dcs"], 1);
  EXPECT_EQ(data["me"]["pending_buffer_bytes"], 4096);
  EXPECT_TRUE(data["api_requests_total"].is_number_unsigned());

  auto user = h.req("GET", "/v1/users/alice");
  ASSERT_EQ(user.status, 200);
  auto user_data = parse_json(user)["data"]["user"];
  EXPECT_EQ(user_data["stats"]["active_connections"], 1);
  EXPECT_EQ(user_data["stats"]["unique_ips_active"], 1);
  EXPECT_EQ(user_data["stats"]["unique_ips_seen"], 2);
  EXPECT_EQ(user_data["stats"]["payload_bytes_c2s"], 11);
  EXPECT_EQ(user_data["stats"]["payload_bytes_s2c"], 22);
}

TEST(HttpHistoryTest, StatusExposesCalendarEstimateContract) {
  Harness h(StoreOptions{}, HttpOptions{}, true);
  ASSERT_TRUE(h.stats().rotate_ip_history(kHistoryTue1030));
  ASSERT_TRUE(h.stats().observe_ip_history({1}));
  ASSERT_TRUE(h.stats().observe_ip_history({1}));
  ASSERT_TRUE(h.stats().observe_ip_history({2}));
  ASSERT_TRUE(h.stats().observe_ip_history_active({1}));
  h.stats().set_unique_ip_min_bytes(1048576);

  auto response = h.req("GET", "/v1/status");
  ASSERT_EQ(response.status, 200);
  auto data = parse_json(response)["data"];
  ASSERT_TRUE(data["unique_ip_history"].is_object());
  const auto& history = data["unique_ip_history"];
  EXPECT_EQ(history["hour"]["estimate"], 2);
  EXPECT_EQ(history["day"]["estimate"], 2);
  EXPECT_EQ(history["week"]["estimate"], 2);
  EXPECT_EQ(history["hour_active"]["estimate"], 1);
  EXPECT_EQ(history["day_active"]["estimate"], 1);
  EXPECT_EQ(history["week_active"]["estimate"], 1);
  EXPECT_EQ(history["min_bytes"], 1048576);
  EXPECT_EQ(history["hour"]["started_at"], kHistoryTue1030 - 1800);
  EXPECT_TRUE(history["approximate"].get<bool>());
  EXPECT_DOUBLE_EQ(history["relative_standard_error"].get<double>(), 0.0325);
  EXPECT_EQ(history["timezone"], "UTC");
  EXPECT_EQ(history["week_starts"], "Monday");
  EXPECT_FALSE(history["persistence_enabled"].get<bool>());
  EXPECT_EQ(history["persistence_failures"], 0);
  EXPECT_EQ(history["observation_failures"], 0);
  EXPECT_TRUE(data["unique_ips_active"].is_number_unsigned());
}

// ---------------------------------------------------------------------------
// HTTP: CRUD, redaction, ETag
// ---------------------------------------------------------------------------

TEST(HttpCrudTest, CrudLifecycleRedactsSecretsAndReturnsThemOnce) {
  Harness h;
  auto created = h.req("POST", "/v1/users", R"({"name":"alice"})");
  ASSERT_EQ(created.status, 201) << created.body;
  auto created_json = parse_json(created);
  EXPECT_EQ(created_json["data"]["revision"], 1);
  EXPECT_TRUE(created_json["data"]["applied"].get<bool>());
  EXPECT_EQ(created_json["data"]["user"]["name"], "alice");
  EXPECT_EQ(created_json["data"]["user"]["enabled"], true);
  EXPECT_TRUE(created_json["data"]["user"]["max_connections"].is_null());
  EXPECT_EQ(created_json["data"]["user"]["generation"], 1);
  ASSERT_TRUE(created_json["data"]["secret"].is_string());
  const std::string secret = created_json["data"]["secret"].get<std::string>();
  EXPECT_EQ(secret.size(), 32u);
  EXPECT_EQ(created_json["data"]["user"].contains("secret"), false);

  auto list = h.req("GET", "/v1/users");
  ASSERT_EQ(list.status, 200);
  EXPECT_EQ(header_value(list, "etag"), "\"1\"");
  EXPECT_EQ(list.body.find(secret), std::string::npos);
  EXPECT_EQ(parse_json(list)["data"]["users"].size(), 1u);

  auto detail = h.req("GET", "/v1/users/alice");
  ASSERT_EQ(detail.status, 200);
  EXPECT_EQ(detail.body.find(secret), std::string::npos);
  EXPECT_EQ(parse_json(detail)["data"]["user"]["name"], "alice");

  auto patched = h.req("PATCH", "/v1/users/alice", R"({"enabled":false})",
                       kToken, {{"If-Match", "\"1\""}});
  ASSERT_EQ(patched.status, 200) << patched.body;
  auto patched_json = parse_json(patched);
  EXPECT_EQ(patched_json["data"]["revision"], 2);
  EXPECT_EQ(patched_json["data"]["user"]["enabled"], false);
  EXPECT_EQ(patched_json["data"]["user"]["generation"], 2);
  EXPECT_EQ(header_value(patched, "etag"), "\"2\"");
  EXPECT_EQ(patched.body.find(secret), std::string::npos);

  auto rotated = h.req("POST", "/v1/users/alice/rotate-secret", "{}",
                       kToken, {{"If-Match", "\"2\""}});
  ASSERT_EQ(rotated.status, 200) << rotated.body;
  auto rotated_json = parse_json(rotated);
  const std::string new_secret = rotated_json["data"]["secret"].get<std::string>();
  EXPECT_NE(new_secret, secret);
  EXPECT_EQ(new_secret.size(), 32u);
  EXPECT_EQ(rotated_json["data"]["user"]["generation"], 3);
  EXPECT_EQ(rotated.body.find(secret), std::string::npos);

  auto capped = h.req("PATCH", "/v1/users/alice", R"({"max_connections":2})",
                      kToken, {{"If-Match", "\"3\""}});
  ASSERT_EQ(capped.status, 200) << capped.body;
  EXPECT_EQ(parse_json(capped)["data"]["user"]["max_connections"], 2);
  EXPECT_EQ(parse_json(capped)["data"]["user"]["generation"], 3);

  auto unlimited = h.req("PATCH", "/v1/users/alice",
                         R"({"max_connections":null})", kToken,
                         {{"If-Match", "\"4\""}});
  ASSERT_EQ(unlimited.status, 200) << unlimited.body;
  EXPECT_TRUE(parse_json(unlimited)["data"]["user"]["max_connections"].is_null());
  EXPECT_EQ(parse_json(unlimited)["data"]["user"]["generation"], 3);

  auto deleted = h.req("DELETE", "/v1/users/alice", "", kToken,
                       {{"If-Match", "\"5\""}});
  ASSERT_EQ(deleted.status, 200) << deleted.body;
  auto deleted_json = parse_json(deleted);
  EXPECT_TRUE(deleted_json["data"]["deleted"].get<bool>());
  EXPECT_EQ(deleted_json["data"]["revision"], 6);
  EXPECT_EQ(parse_json(h.req("GET", "/v1/users"))["data"]["users"].size(), 0u);
  EXPECT_EQ(h.req("GET", "/v1/users/alice").status, 404);
}

TEST(HttpCrudTest, RotationAcceptsSuppliedSecretOnce) {
  Harness h;
  ASSERT_EQ(h.req("POST", "/v1/users", make_user_body("alice")).status, 201);
  auto rotated = h.req("POST", "/v1/users/alice/rotate-secret",
                       std::string("{\"secret\":\"") + kHexC + "\"}");
  ASSERT_EQ(rotated.status, 200) << rotated.body;
  auto j = parse_json(rotated);
  EXPECT_EQ(j["data"]["secret"], kHexC);
  EXPECT_EQ(j["data"]["user"]["generation"], 2);
  EXPECT_EQ(h.store().snapshot()->find("alice")->secret_hex, kHexC);
}

TEST(HttpCrudTest, ETagConflictsAndValidation) {
  Harness h;
  CreateUserRequest seeded;
  seeded.name = "alice";
  ASSERT_TRUE(h.store().create_user(seeded).ok());

  auto stale_patch = h.req("PATCH", "/v1/users/alice", R"({"enabled":false})",
                           kToken, {{"If-Match", "\"999\""}});
  EXPECT_EQ(stale_patch.status, 412) << stale_patch.body;
  EXPECT_EQ(parse_json(stale_patch)["error"]["type"], "revision_conflict");
  EXPECT_TRUE(h.store().snapshot()->find("alice")->enabled);

  auto stale_delete = h.req("DELETE", "/v1/users/alice", "", kToken,
                            {{"If-Match", "\"999\""}});
  EXPECT_EQ(stale_delete.status, 412);
  EXPECT_NE(h.store().snapshot()->find("alice"), nullptr);

  auto invalid = h.req("PATCH", "/v1/users/alice", R"({"enabled":false})",
                       kToken, {{"If-Match", "not-an-etag"}});
  EXPECT_EQ(invalid.status, 400);

  auto multiple = h.req("PATCH", "/v1/users/alice", R"({"enabled":false})",
                        kToken, {{"If-Match", "\"1\", \"2\""}});
  EXPECT_EQ(multiple.status, 400) << multiple.body;
  EXPECT_EQ(parse_json(multiple)["error"]["type"], "invalid_field");
  EXPECT_TRUE(h.store().snapshot()->find("alice")->enabled);

  // A quoted but unknown ETag is a stale precondition, not a syntax error.
  auto quoted_stale = h.req("PATCH", "/v1/users/alice", R"({"enabled":false})",
                            kToken, {{"If-Match", "\"stale-revision\""}});
  EXPECT_EQ(quoted_stale.status, 412) << quoted_stale.body;
  EXPECT_TRUE(h.store().snapshot()->find("alice")->enabled);

  auto current = h.req("PATCH", "/v1/users/alice", R"({"enabled":false})",
                       kToken, {{"If-Match", "\"1\""}});
  EXPECT_EQ(current.status, 200);
  auto reuse = h.req("PATCH", "/v1/users/alice", R"({"enabled":true})",
                     kToken, {{"If-Match", "\"1\""}});
  EXPECT_EQ(reuse.status, 412);
  EXPECT_EQ(h.store().snapshot()->revision, 2u);
}

TEST(HttpCrudTest, PendingRuntimeAcknowledgementReturns202NotLies) {
  StoreOptions options;
  std::atomic<int> calls{0};
  options.ack_timeout = 30ms;
  options.ack_hook = [&calls](uint64_t, std::chrono::milliseconds) {
    calls.fetch_add(1);
    return false;
  };
  Harness h(options);
  auto response = h.req("POST", "/v1/users", R"({"name":"alice"})");
  ASSERT_EQ(response.status, 202) << response.body;
  auto j = parse_json(response);
  EXPECT_EQ(j["data"]["revision"], 1);
  EXPECT_FALSE(j["data"]["applied"].get<bool>());
  EXPECT_TRUE(j["data"]["pending"].get<bool>());
  EXPECT_EQ(header_value(response, "etag"), "\"1\"");
  EXPECT_EQ(calls.load(), 1);
  ASSERT_NE(h.store().snapshot()->find("alice"), nullptr);
  EXPECT_EQ(h.req("GET", "/v1/users/alice").status, 200);
}

TEST(HttpCrudTest, AcknowledgedRuntimeReturns201) {
  StoreOptions options;
  options.ack_hook = [](uint64_t revision, std::chrono::milliseconds) {
    return revision > 0;
  };
  Harness h(options);
  auto response = h.req("POST", "/v1/users", R"({"name":"alice"})");
  ASSERT_EQ(response.status, 201) << response.body;
  EXPECT_TRUE(parse_json(response)["data"]["applied"].get<bool>());
  EXPECT_EQ(parse_json(response)["data"].contains("pending"), false);
}

// ---------------------------------------------------------------------------
// HTTP: validation and method handling
// ---------------------------------------------------------------------------

TEST(HttpValidationTest, RejectsUnknownFieldsTypesAndOutOfRangeValues) {
  Harness h;
  auto expect_error = [&](const std::string& method, const std::string& path,
                          const std::string& body, int status,
                          const std::string& type) {
    auto r = h.req(method, path, body);
    EXPECT_EQ(r.status, status) << body << " -> " << r.body;
    if (status >= 400) {
      EXPECT_EQ(parse_json(r)["error"]["type"], type) << body;
    }
  };

  expect_error("POST", "/v1/users", R"({"name":"bob","quota":3})", 400,
               "unknown_field");
  expect_error("POST", "/v1/users", R"({"name":"bad name"})", 400,
               "invalid_name");
  expect_error("POST", "/v1/users", R"({"name":"bob","secret":"xyz"})", 400,
               "invalid_secret");
  expect_error("POST", "/v1/users", R"({"name":"bob","secret":null})", 400,
               "invalid_field");
  expect_error("POST", "/v1/users", R"({"name":"bob","enabled":null})", 400,
               "invalid_field");
  expect_error("POST", "/v1/users", R"({"name":"bob","enabled":"yes"})", 400,
               "invalid_field");
  expect_error("POST", "/v1/users", R"({"name":"bob","max_connections":0})", 400,
               "invalid_field");
  expect_error("POST", "/v1/users", R"({"name":"bob","max_connections":-1})", 400,
               "invalid_field");
  expect_error("POST", "/v1/users", R"({"name":"bob","max_connections":1000001})",
               400, "invalid_field");
  expect_error("POST", "/v1/users", R"({"name":"bob","max_connections":"3"})",
               400, "invalid_field");
  expect_error("POST", "/v1/users", R"({"name":"bob","max_connections":1.5})",
               400, "invalid_field");
  expect_error("POST", "/v1/users", R"({"name":123})", 400, "invalid_field");
  expect_error("POST", "/v1/users", R"({"name":null})", 400, "invalid_field");
  expect_error("POST", "/v1/users", R"({"secret":"00112233445566778899aabbccddeeff"})",
               400, "invalid_name");
  expect_error("POST", "/v1/users", "{", 400, "invalid_json");
  expect_error("POST", "/v1/users", "[]", 400, "invalid_request");
  expect_error("POST", "/v1/users", "", 400, "invalid_request");

  auto created_alice = h.req("POST", "/v1/users", make_user_body("alice"));
  ASSERT_EQ(created_alice.status, 201);
  const std::string alice_secret =
      parse_json(created_alice)["data"]["secret"].get<std::string>();
  expect_error("POST", "/v1/users", make_user_body("alice"), 409,
               "duplicate_name");
  expect_error("POST", "/v1/users",
               make_user_body("bob", alice_secret), 409,
               "duplicate_secret");
  expect_error("PATCH", "/v1/users/alice", R"({"quota":1})", 400,
               "unknown_field");
  expect_error("PATCH", "/v1/users/alice", "{}", 400, "invalid_request");
  expect_error("PATCH", "/v1/users/alice", R"({"enabled":null})", 400,
               "invalid_field");
  expect_error("PATCH", "/v1/users/alice", R"({"max_connections":0})", 400,
               "invalid_field");
  expect_error("PATCH", "/v1/users/ghost", R"({"enabled":false})", 404,
               "not_found");
  expect_error("DELETE", "/v1/users/ghost", "", 404, "not_found");
  expect_error("POST", "/v1/users/ghost/rotate-secret", "{}", 404,
               "not_found");
  expect_error("GET", "/v1/users/ghost", "", 404, "not_found");
  expect_error("GET", "/v1/unknown", "", 404, "not_found");
  expect_error("PUT", "/v1/users", "", 405, "method_not_allowed");
  EXPECT_EQ(h.store().snapshot()->revision, 1u);
}

TEST(HttpValidationTest, RejectsOversizedBodyWithoutMutation) {
  HttpOptions options;
  options.max_body_bytes = 128;
  Harness h({}, options);
  std::string large = R"({"name":"alice","padding":")" + std::string(400, 'x') +
                      R"("})";
  auto response = h.req("POST", "/v1/users", large);
  EXPECT_EQ(response.status, 413) << response.body;
  EXPECT_EQ(parse_json(response)["error"]["type"], "body_too_large");
  EXPECT_EQ(h.store().snapshot()->revision, 0u);
  // Server must still be usable after rejecting the oversized request.
  auto healthy = h.req("GET", "/v1/health");
  EXPECT_EQ(healthy.status, 200);
}

// ---------------------------------------------------------------------------
// HTTP: metrics and information leak checks
// ---------------------------------------------------------------------------

TEST(HttpMetricsTest, MetricsRequireTokenAndEscapeLabelsWithoutSecrets) {
  Harness h;
  h.stats().set_build_info("build\"quoted\nline");
  auto created = h.req("POST", "/v1/users", R"({"name":"alice"})");
  ASSERT_EQ(created.status, 201);
  const std::string secret = parse_json(created)["data"]["secret"].get<std::string>();

  auto response = h.req("GET", "/metrics");
  ASSERT_EQ(response.status, 200) << response.body;
  EXPECT_NE(header_value(response, "content-type").find("text/plain"),
            std::string::npos);
  EXPECT_EQ(header_value(response, "etag"), "\"1\"");
  EXPECT_NE(response.body.find("mtdd_build_info"), std::string::npos);
  EXPECT_NE(response.body.find("mtdd_connections_active"), std::string::npos);
  EXPECT_NE(response.body.find("mtdd_uptime_seconds"), std::string::npos);
  EXPECT_NE(response.body.find("mtdd_user_connections_active{user=\"alice\"}"),
            std::string::npos);
  EXPECT_EQ(response.body.find(secret), std::string::npos);
  EXPECT_EQ(response.body.find(kToken), std::string::npos);
  EXPECT_EQ(response.body.find("127.0.0.1"), std::string::npos);
  EXPECT_NE(response.body.find("version=\"build\\\"quoted\\nline\""),
            std::string::npos);

  // API request counting is exposed with bounded route templates, not raw paths.
  auto after = h.req("GET", "/metrics");
  EXPECT_NE(after.body.find(
                "mtdd_api_requests_total{route=\"/metrics\",method=\"GET\",status=\"200\"}"),
            std::string::npos);
  EXPECT_EQ(after.body.find("/v1/users/alice/secret"), std::string::npos);
}

TEST(HttpMetricsTest, RejectionsReasonsAreBoundedLabels) {
  Harness h;
  h.stats().connection_rejected(RejectReason::overload);
  h.stats().connection_rejected(RejectReason::auth_failed);
  h.stats().handshake(HandshakeResult::replay);
  auto response = h.req("GET", "/metrics");
  ASSERT_EQ(response.status, 200);
  EXPECT_NE(response.body.find(
                "mtdd_connections_rejected_total{reason=\"overload\"} 1"),
            std::string::npos);
  EXPECT_NE(response.body.find(
                "mtdd_handshakes_total{result=\"replay\"} 1"),
            std::string::npos);
  EXPECT_EQ(response.body.find("reason=\"raw-client-string\""), std::string::npos);
}

// ---------------------------------------------------------------------------
// HTTP: rate limiting, connection cap, lifecycle
// ---------------------------------------------------------------------------

TEST(HttpLimitsTest, PerSourceRateLimitRejectsWithoutBreakingServer) {
  HttpOptions options;
  options.rate_limit_per_second = 5.0;
  options.rate_limit_burst = 5.0;
  options.global_rate_limit_per_second = 1000.0;
  options.global_rate_limit_burst = 1000.0;
  Harness h({}, options);

  int ok = 0;
  int limited = 0;
  for (int i = 0; i < 10; ++i) {
    auto response = h.req("GET", "/v1/health");
    if (response.status == 200) ++ok;
    if (response.status == 429) ++limited;
    EXPECT_TRUE(response.status == 200 || response.status == 429)
        << response.status << " " << response.body;
  }
  EXPECT_GE(ok, 1);
  EXPECT_GE(limited, 1);
  auto after = h.req("GET", "/v1/health");
  EXPECT_TRUE(after.status == 200 || after.status == 429);
}

TEST(HttpLimitsTest, ConnectionCapPausesAcceptanceUntilCapacityReturns) {
  HttpOptions options;
  options.max_connections = 1;
  options.request_deadline = 5000ms;
  Harness h({}, options);

  // Occupy the only slot with a live keep-alive HTTP connection.
  int raw = connect_localhost(h.port(), 1000);
  ASSERT_GE(raw, 0);
  const std::string keep_alive =
      "GET /v1/health HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n";
  ASSERT_TRUE(send_all(raw, keep_alive, 1000));
  std::this_thread::sleep_for(150ms);

  // The cap pauses the listener, so this connection waits in the backlog and
  // never gets a response while the slot is occupied.
  auto queued = h.req("GET", "/v1/health", {}, kToken, {},
                      std::chrono::milliseconds(800));
  EXPECT_EQ(queued.status, 0) << queued.body;

  ::close(raw);
  std::this_thread::sleep_for(300ms);
  auto recovered = h.req("GET", "/v1/health", {}, kToken, {},
                         std::chrono::milliseconds(3000));
  EXPECT_EQ(recovered.status, 200) << recovered.body;
}

TEST(HttpLimitsTest, AcceptBurstRetainsNearCap) {
  HttpOptions options;
  options.max_connections = 4;
  options.request_deadline = 1000ms;
  Harness h({}, options);

  std::vector<int> clients;
  for (int i = 0; i < 24; ++i) {
    int fd = connect_localhost(h.port(), 300);
    if (fd >= 0) clients.push_back(fd);
  }
  std::this_thread::sleep_for(250ms);
  // Listener + at most the cap, with a small accept-batch allowance.
  EXPECT_LE(count_server_sockets(h.port()), 8u);

  for (int fd : clients) ::close(fd);
  bool healthy = false;
  const auto deadline = std::chrono::steady_clock::now() + 4000ms;
  while (std::chrono::steady_clock::now() < deadline) {
    auto response = h.req("GET", "/v1/health", {}, kToken, {},
                          std::chrono::milliseconds(500));
    if (response.status == 200) {
      healthy = true;
      break;
    }
    std::this_thread::sleep_for(50ms);
  }
  EXPECT_TRUE(healthy);
  EXPECT_LE(count_server_sockets(h.port()), 6u);
}

TEST(HttpLimitsTest, AbsolutePreRequestDeadlineReclaimsSlowloris) {
  HttpOptions options;
  options.max_connections = 2;
  options.request_deadline = 300ms;
  Harness h({}, options);

  std::vector<int> clients;
  const std::string partial = "GET /v1/health HTTP/1.1\r\nHost: 127.0.0.1\r\n";
  for (int i = 0; i < 8; ++i) {
    int fd = connect_localhost(h.port(), 1000);
    if (fd < 0) continue;
    clients.push_back(fd);
    ASSERT_TRUE(send_all(fd, partial, 1000));
    std::this_thread::sleep_for(20ms);
  }
  ASSERT_FALSE(clients.empty());

  std::size_t peak = 0;
  const auto deadline = std::chrono::steady_clock::now() + 1500ms;
  std::size_t next = 0;
  while (std::chrono::steady_clock::now() < deadline) {
    // One byte per interval keeps libevent's inactivity timer alive; only the
    // admission's absolute deadline may terminate these sockets.
    if (!clients.empty()) {
      const char byte = 'A';
      (void)::send(clients[next % clients.size()], &byte, 1, MSG_NOSIGNAL);
      ++next;
    }
    std::this_thread::sleep_for(100ms);
    peak = std::max(peak, count_server_sockets(h.port()));
  }
  EXPECT_LE(peak, 6u) << "server-side sockets must stay near the cap";

  for (int fd : clients) ::close(fd);

  bool healthy = false;
  const auto health_deadline = std::chrono::steady_clock::now() + 4000ms;
  while (std::chrono::steady_clock::now() < health_deadline) {
    auto response = h.req("GET", "/v1/health", {}, kToken, {},
                          std::chrono::milliseconds(500));
    if (response.status == 200) {
      healthy = true;
      break;
    }
    std::this_thread::sleep_for(50ms);
  }
  EXPECT_TRUE(healthy) << "authenticated health starved by slowloris";
  EXPECT_LE(count_server_sockets(h.port()), 6u);
}

TEST(HttpLimitsTest, EarlyEofBeforeFirstRequestDoesNotWedgeOrLeak) {
  HttpOptions options;
  options.max_connections = 2;
  options.request_deadline = 500ms;
  Harness h({}, options);

  for (int i = 0; i < 60; ++i) {
    int fd = connect_localhost(h.port(), 500);
    if (fd >= 0) ::close(fd);
  }

  bool healthy = false;
  const auto deadline = std::chrono::steady_clock::now() + 4000ms;
  while (std::chrono::steady_clock::now() < deadline) {
    auto response = h.req("GET", "/v1/health", {}, kToken, {},
                          std::chrono::milliseconds(500));
    if (response.status == 200) {
      healthy = true;
      break;
    }
    std::this_thread::sleep_for(50ms);
  }
  EXPECT_TRUE(healthy);
  EXPECT_LE(count_server_sockets(h.port()), 5u);
}

TEST(HttpLifecycleTest, StopWithActivePreRequestConnectionsJoinsSafely) {
  TempDir dir;
  auto store = open_store_or_throw(dir.file("users.json"));
  Statistics stats;
  HttpOptions options;
  options.bearer_token = kToken;
  options.max_connections = 8;
  options.request_deadline = 5000ms;
  ControlServer server(store, stats, options);
  ASSERT_TRUE(server.start().ok());

  std::vector<int> clients;
  for (int i = 0; i < 4; ++i) {
    int fd = connect_localhost(server.port(), 1000);
    if (fd >= 0) clients.push_back(fd);
  }
  std::this_thread::sleep_for(100ms);
  server.stop();
  EXPECT_FALSE(server.running());
  for (int fd : clients) ::close(fd);
}

TEST(HttpLifecycleTest, StopWithPendingInstallEventsIsSafe) {
  TempDir dir;
  auto store = open_store_or_throw(dir.file("users.json"));
  Statistics stats;
  HttpOptions options;
  options.bearer_token = kToken;
  options.max_connections = 8;
  options.request_deadline = 5000ms;

  // No sleep between connect and stop: the zero-time install event may still be
  // pending. stop() must cancel it before deleting the admission (ASan/LSan).
  for (int round = 0; round < 10; ++round) {
    ControlServer server(store, stats, options);
    auto started = server.start();
    ASSERT_TRUE(started.ok()) << started.error().message;
    std::vector<int> clients;
    for (int i = 0; i < 4; ++i) {
      int fd = connect_localhost(server.port(), 300);
      if (fd >= 0) clients.push_back(fd);
    }
    server.stop();
    EXPECT_FALSE(server.running());
    for (int fd : clients) ::close(fd);
  }
}

TEST(HttpLifecycleTest, StartStopIsIdempotentAndJoinsThread) {
  TempDir dir;
  auto store = open_store_or_throw(dir.file("users.json"));
  Statistics stats;
  HttpOptions options;
  options.bearer_token = kToken;
  ControlServer server(store, stats, options);
  auto started = server.start();
  ASSERT_TRUE(started.ok()) << started.error().message;
  EXPECT_TRUE(server.running());
  EXPECT_GT(started.value(), 0);
  auto again = server.start();
  EXPECT_FALSE(again.ok());
  EXPECT_EQ(again.error().code, ErrorCode::invalid_config);
  server.stop();
  EXPECT_FALSE(server.running());
  server.stop();
  EXPECT_EQ(server.port(), started.value());
}

TEST(HttpLifecycleTest, RejectsNonFiniteRateLimits) {
  TempDir dir;
  auto store = open_store_or_throw(dir.file("users.json"));
  Statistics stats;
  for (int variant = 0; variant < 4; ++variant) {
    HttpOptions options;
    options.bearer_token = kToken;
    const double inf = std::numeric_limits<double>::infinity();
    if (variant == 0) options.rate_limit_per_second = inf;
    if (variant == 1) options.rate_limit_burst = inf;
    if (variant == 2) options.global_rate_limit_per_second = inf;
    if (variant == 3) options.global_rate_limit_burst = inf;
    ControlServer server(store, stats, options);
    auto started = server.start();
    ASSERT_FALSE(started.ok()) << "variant " << variant;
    EXPECT_EQ(started.error().code, ErrorCode::invalid_config);
    EXPECT_FALSE(server.running());
  }
}

TEST(HttpLifecycleTest, EmptyTokenIsRejected) {
  TempDir dir;
  auto store = open_store_or_throw(dir.file("users.json"));
  Statistics stats;
  HttpOptions options;
  options.bearer_token.clear();
  ControlServer server(store, stats, options);
  auto started = server.start();
  ASSERT_FALSE(started.ok());
  EXPECT_EQ(started.error().code, ErrorCode::invalid_config);
  EXPECT_FALSE(server.running());
}

TEST(HttpLifecycleTest, ConcurrentRequestsAreSerializedSafely) {
  Harness h;
  std::atomic<int> ok{0};
  std::vector<std::thread> threads;
  for (int i = 0; i < 4; ++i) {
    threads.emplace_back([&] {
      for (int j = 0; j < 3; ++j) {
        auto response = h.req("GET", "/v1/status");
        if (response.status == 200) ok.fetch_add(1);
      }
    });
  }
  for (auto& thread : threads) thread.join();
  EXPECT_EQ(ok.load(), 12);
}


}  // namespace
