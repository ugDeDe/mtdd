#include "../support/control_fixture.hpp"

namespace {

TEST(StatisticsTest, CountersAndSnapshot) {
  Statistics stats;
  stats.set_ready(true);
  stats.set_build_info("1.2.3");
  stats.connection_accepted();
  stats.connection_accepted();
  stats.connection_closed();
  stats.connection_rejected(RejectReason::overload);
  stats.connection_rejected(RejectReason::auth_failed);
  stats.handshake(HandshakeResult::success);
  stats.handshake(HandshakeResult::failure);

  auto alice = stats.user("alice");
  ASSERT_NE(alice, nullptr);
  alice->connection_opened();
  alice->add_payload(Direction::client_to_server, 123);
  alice->add_payload(Direction::server_to_client, 456);
  alice->set_active_unique_ips(3);
  alice->set_qualified_unique_ips(1);
  stats.set_active_unique_ips(7);
  stats.set_qualified_unique_ips(4);
  stats.set_unique_ip_min_bytes(2048);

  stats.set_buffer_bytes(BufferState::queued, 10);
  stats.set_buffer_bytes(BufferState::pending_write, 20);
  stats.add_backpressure(Direction::client_to_server);
  stats.set_replay_cache_entries(5);
  stats.api_request(ApiRoute::users, ApiMethod::get, 200);
  stats.api_request(ApiRoute::users, ApiMethod::get, 200);
  stats.api_request(ApiRoute::user, ApiMethod::post, 405);
  stats.me_connected(2, true);
  stats.me_reconnect(2);
  stats.me_request(2, MeResult::success);
  stats.me_request(2, MeResult::timeout);
  stats.me_pending_buffer_bytes(77);

  auto snapshot = stats.snapshot();
  EXPECT_TRUE(snapshot.ready);
  EXPECT_EQ(snapshot.build_version, "1.2.3");
  EXPECT_EQ(snapshot.connections_accepted_total, 2u);
  EXPECT_EQ(snapshot.connections_active, 1u);
  EXPECT_EQ(snapshot.active_unique_ips, 7u);
  EXPECT_EQ(snapshot.qualified_unique_ips, 4u);
  EXPECT_EQ(snapshot.unique_ip_min_bytes, 2048u);
  EXPECT_EQ(snapshot.connections_rejected_total, 2u);
  EXPECT_EQ(snapshot.rejected_by_reason["overload"], 1u);
  EXPECT_EQ(snapshot.rejected_by_reason["auth_failed"], 1u);
  EXPECT_EQ(snapshot.handshakes_by_result["success"], 1u);
  EXPECT_EQ(snapshot.handshakes_by_result["failure"], 1u);
  ASSERT_EQ(snapshot.users.count("alice"), 1u);
  EXPECT_EQ(snapshot.users["alice"].active_connections, 1u);
  EXPECT_EQ(snapshot.users["alice"].unique_ips_active, 3u);
  EXPECT_EQ(snapshot.users["alice"].unique_ips_qualified, 1u);
  EXPECT_EQ(snapshot.users["alice"].payload_c2s_bytes, 123u);
  EXPECT_EQ(snapshot.users["alice"].payload_s2c_bytes, 456u);
  EXPECT_EQ(snapshot.buffer_bytes[static_cast<size_t>(BufferState::queued)], 10u);
  EXPECT_EQ(snapshot.buffer_bytes[static_cast<size_t>(BufferState::pending_write)], 20u);
  EXPECT_EQ(snapshot.backpressure_c2s_total, 1u);
  EXPECT_EQ(snapshot.replay_cache_entries, 5u);
  EXPECT_EQ(snapshot.api_requests_total, 3u);
  EXPECT_EQ(snapshot.me_pending_buffer_bytes, 77u);
  ASSERT_EQ(snapshot.me_dcs.count("2"), 1u);
  EXPECT_TRUE(snapshot.me_dcs["2"].connected);
  EXPECT_EQ(snapshot.me_dcs["2"].reconnects_total, 1u);
  EXPECT_EQ(snapshot.me_dcs["2"].requests_success, 1u);
  EXPECT_EQ(snapshot.me_dcs["2"].requests_timeout, 1u);
}

TEST(StatisticsTest, UniqueIpGaugesAreRenderedWithoutIpLabels) {
  Statistics stats;
  stats.set_active_unique_ips(9);
  auto alice = stats.user("alice");
  ASSERT_NE(alice, nullptr);
  alice->set_active_unique_ips(2);
  EXPECT_EQ(alice->active_unique_ips(), 2u);
  stats.set_qualified_unique_ips(5);
  alice->set_qualified_unique_ips(1);
  EXPECT_EQ(alice->qualified_unique_ips(), 1u);
  stats.set_unique_ip_min_bytes(4096);
  const std::string text = stats.prometheus_text();
  // "active" is the byte-threshold count; "seen" is the handshake count.
  EXPECT_NE(text.find("mtdd_unique_ips_active 5"), std::string::npos);
  EXPECT_NE(text.find("mtdd_unique_ips_seen 9"), std::string::npos);
  EXPECT_NE(text.find("mtdd_unique_ips_min_bytes 4096"), std::string::npos);
  EXPECT_NE(text.find("# HELP mtdd_unique_ips_seen "), std::string::npos);
  EXPECT_NE(text.find("mtdd_user_unique_ips_active{user=\"alice\"} 1"),
            std::string::npos);
  EXPECT_NE(text.find("mtdd_user_unique_ips_seen{user=\"alice\"} 2"),
            std::string::npos);
  EXPECT_EQ(text.find("127.0.0.1"), std::string::npos);
}

TEST(StatisticsTest, IpHistoryObservesDuplicatesAndRotatesPeriods) {
  Statistics stats;
  EXPECT_FALSE(stats.observe_ip_history({}));
  stats.enable_ip_history();
  EXPECT_THROW(stats.enable_ip_history(), std::logic_error);

  const std::array<std::uint8_t, 16> a{1};
  const std::array<std::uint8_t, 16> b{2};
  ASSERT_TRUE(stats.rotate_ip_history(kHistoryTue1030));
  ASSERT_TRUE(stats.observe_ip_history(a));
  ASSERT_TRUE(stats.observe_ip_history(a));  // idempotent inside a period
  ASSERT_TRUE(stats.observe_ip_history(b));
  auto snapshot = stats.snapshot();
  EXPECT_EQ(snapshot.unique_ip_history.hour, 2U);
  EXPECT_EQ(snapshot.unique_ip_history.day, 2U);
  EXPECT_EQ(snapshot.unique_ip_history.week, 2U);
  EXPECT_EQ(snapshot.unique_ip_history.hour_started_at, kHistoryTue1030 - 1800);
  EXPECT_GT(snapshot.unique_ip_history.collection_started_at, 0);
  EXPECT_FALSE(snapshot.unique_ip_history.persistence_enabled);
  EXPECT_EQ(snapshot.ip_history_observation_failures, 0U);

  ASSERT_TRUE(stats.rotate_ip_history(kHistoryTue1100));
  snapshot = stats.snapshot();
  EXPECT_EQ(snapshot.unique_ip_history.hour, 0U);
  EXPECT_EQ(snapshot.unique_ip_history.day, 2U);
  EXPECT_EQ(snapshot.unique_ip_history.week, 2U);
  ASSERT_TRUE(stats.observe_ip_history(a));
  ASSERT_TRUE(stats.observe_ip_history(b));
  snapshot = stats.snapshot();
  EXPECT_EQ(snapshot.unique_ip_history.hour, 2U);
  EXPECT_EQ(snapshot.unique_ip_history.day, 2U);

  ASSERT_TRUE(stats.rotate_ip_history(kHistoryNextMon));
  snapshot = stats.snapshot();
  EXPECT_EQ(snapshot.unique_ip_history.hour, 0U);
  EXPECT_EQ(snapshot.unique_ip_history.day, 0U);
  EXPECT_EQ(snapshot.unique_ip_history.week, 0U);
  EXPECT_EQ(snapshot.unique_ip_history.week_started_at, kHistoryNextMon);
}

TEST(StatisticsTest, IpHistoryMetricsUseFixedPeriodsAndNoIpLabels) {
  Statistics stats;
  stats.enable_ip_history();
  ASSERT_TRUE(stats.rotate_ip_history(kHistoryTue1030));
  ASSERT_TRUE(stats.observe_ip_history({7}));
  const std::string text = stats.prometheus_text();
  EXPECT_NE(text.find("mtdd_unique_ips_estimate{period=\"hour\"} 1"),
            std::string::npos);
  EXPECT_NE(text.find("mtdd_unique_ips_estimate{period=\"day\"} 1"),
            std::string::npos);
  EXPECT_NE(text.find("mtdd_unique_ips_estimate{period=\"week\"} 1"),
            std::string::npos);
  EXPECT_NE(text.find("mtdd_unique_ips_period_start_seconds{period=\"hour\"} "),
            std::string::npos);
  EXPECT_NE(text.find("mtdd_unique_ips_collection_started_seconds "),
            std::string::npos);
  EXPECT_NE(text.find("mtdd_unique_ips_checkpoint_failures_total 0"),
            std::string::npos);
  EXPECT_NE(text.find("mtdd_unique_ips_observation_failures_total 0"),
            std::string::npos);
  EXPECT_EQ(text.find("127.0.0.1"), std::string::npos);
  EXPECT_EQ(text.find("ip=\""), std::string::npos);
}

TEST(StatisticsTest, ActiveIpHistoryIsSeparateFromSeenHistory) {
  Statistics stats;
  stats.enable_ip_history();
  ASSERT_TRUE(stats.rotate_ip_history(kHistoryTue1030));
  ASSERT_TRUE(stats.observe_ip_history({7}));
  ASSERT_TRUE(stats.observe_ip_history({8}));
  ASSERT_TRUE(stats.observe_ip_history_active({7}));
  const std::string text = stats.prometheus_text();
  EXPECT_NE(text.find("mtdd_unique_ips_estimate{period=\"hour\"} 2"), std::string::npos);
  EXPECT_NE(text.find("mtdd_unique_ips_active_estimate{period=\"hour\"} 1"),
            std::string::npos);
  EXPECT_NE(text.find("mtdd_unique_ips_active_estimate{period=\"week\"} 1"),
            std::string::npos);
  EXPECT_NE(text.find("# HELP mtdd_unique_ips_active_estimate "), std::string::npos);
}

TEST(StatisticsTest, UnknownApiStatusIsBucketedAs500Not429) {
  Statistics stats;
  stats.api_request(ApiRoute::health, ApiMethod::get, 418);
  const std::string text = stats.prometheus_text();
  EXPECT_NE(text.find(
                "mtdd_api_requests_total{route=\"/v1/health\",method=\"GET\",status=\"500\"} 1"),
            std::string::npos);
  EXPECT_EQ(text.find("status=\"429\""), std::string::npos);
}

TEST(StatisticsTest, RejectsInvalidUserLabels) {
  Statistics stats;
  EXPECT_EQ(stats.user("bad name"), nullptr);
  EXPECT_EQ(stats.user(std::string(65, 'a')), nullptr);
  EXPECT_EQ(stats.user(""), nullptr);
  EXPECT_NE(stats.user("good.name-1"), nullptr);
}

TEST(StatisticsTest, UserTrackingIsBoundedAndForgettable) {
  Statistics stats(2);
  EXPECT_NE(stats.user("a"), nullptr);
  EXPECT_NE(stats.user("b"), nullptr);
  EXPECT_EQ(stats.user("c"), nullptr);
  EXPECT_EQ(stats.snapshot().users.size(), 2u);
  stats.forget_user("a");
  EXPECT_EQ(stats.snapshot().users.count("a"), 0u);
  EXPECT_NE(stats.user("c"), nullptr);
}

TEST(StatisticsTest, MeDcLabelsAreBoundedAndIncludeSignedCdn) {
  Statistics stats;
  stats.me_connected(-3, true);
  stats.me_connected(203, true);
  stats.me_connected(-203, true);
  stats.me_connected(10000, true);
  auto snapshot = stats.snapshot();
  EXPECT_EQ(snapshot.me_dcs.count("-3"), 1u);
  EXPECT_TRUE(snapshot.me_dcs["203"].connected);
  EXPECT_TRUE(snapshot.me_dcs["-203"].connected);
  EXPECT_EQ(snapshot.me_dcs.count("10000"), 0u);
  ASSERT_EQ(snapshot.me_dcs.count("other"), 1u);
  EXPECT_LE(snapshot.me_dcs.size(), 13u);
}

TEST(PrometheusTest, RendersNativeMetricsAndEscapesLabels) {
  Statistics stats;
  stats.set_ready(true);
  stats.set_build_info("v\"1\\2\n3");
  stats.connection_accepted();
  stats.connection_accepted();
  stats.connection_closed();
  stats.connection_rejected(RejectReason::overload);
  stats.handshake(HandshakeResult::success);
  auto alice = stats.user("alice");
  ASSERT_NE(alice, nullptr);
  alice->connection_opened();
  alice->add_payload(Direction::client_to_server, 123);
  alice->add_payload(Direction::server_to_client, 456);
  alice->set_active_unique_ips(3);
  stats.set_active_unique_ips(7);
  stats.set_buffer_bytes(BufferState::queued, 10);
  stats.add_backpressure(Direction::client_to_server);
  stats.set_replay_cache_entries(5);
  stats.api_request(ApiRoute::users, ApiMethod::get, 200);
  stats.me_connected(2, true);
  stats.me_request(2, MeResult::success);
  stats.me_pending_buffer_bytes(77);

  const std::string text = stats.prometheus_text();

  EXPECT_NE(text.find("mtdd_connections_active 1\n"), std::string::npos);
  EXPECT_NE(text.find("mtdd_connections_accepted_total 2\n"), std::string::npos);
  EXPECT_NE(text.find("mtdd_connections_rejected_total{reason=\"overload\"} 1\n"),
            std::string::npos);
  EXPECT_NE(text.find("mtdd_handshakes_total{result=\"success\"} 1\n"),
            std::string::npos);
  EXPECT_NE(text.find("mtdd_user_connections_active{user=\"alice\"} 1\n"),
            std::string::npos);
  EXPECT_NE(text.find(
                "mtdd_user_payload_bytes_received_total{user=\"alice\",direction=\"c2s\"} 123\n"),
            std::string::npos);
  EXPECT_NE(text.find(
                "mtdd_user_payload_bytes_received_total{user=\"alice\",direction=\"s2c\"} 456\n"),
            std::string::npos);
  EXPECT_NE(text.find("mtdd_buffer_bytes{state=\"queued\"} 10\n"), std::string::npos);
  EXPECT_NE(text.find("mtdd_backpressure_events_total{direction=\"c2s\"} 1\n"),
            std::string::npos);
  EXPECT_NE(text.find("mtdd_replay_cache_entries 5\n"), std::string::npos);
  EXPECT_NE(text.find(
                "mtdd_api_requests_total{route=\"/v1/users\",method=\"GET\",status=\"200\"} 1\n"),
            std::string::npos);
  EXPECT_NE(text.find("mtdd_me_connected{dc=\"2\"} 1\n"), std::string::npos);
  EXPECT_NE(text.find("mtdd_me_requests_total{dc=\"2\",result=\"success\"} 1\n"),
            std::string::npos);
  EXPECT_NE(text.find("mtdd_me_pending_buffer_bytes 77\n"), std::string::npos);
  EXPECT_NE(text.find("mtdd_uptime_seconds "), std::string::npos);
  EXPECT_NE(text.find("mtdd_build_info{version=\"v\\\"1\\\\2\\n3\"} 1"),
            std::string::npos);
  // Escaped label must not introduce a raw newline inside the metric line.
  auto build_pos = text.find("mtdd_build_info{version=");
  ASSERT_NE(build_pos, std::string::npos);
  auto build_end = text.find('\n', build_pos);
  ASSERT_NE(build_end, std::string::npos);
  EXPECT_EQ(text.substr(build_pos, build_end - build_pos).find("3\"} 1"),
            text.substr(build_pos, build_end - build_pos).size() - 5);
  EXPECT_EQ(text.find("unknown"), std::string::npos);
}

// ---------------------------------------------------------------------------
// HTTP: authentication, health, readiness, status
// ---------------------------------------------------------------------------

TEST(StatisticsTest, MeQueueAndAnswerSeriesUseOnlyBoundedDcLabels) {
  Statistics stats;
  stats.me_queue(2, 3, 2, 4096, 8192);
  stats.me_answer(2, MeAnswerResult::received);
  stats.me_answer(2, MeAnswerResult::received);
  stats.me_answer(2, MeAnswerResult::delivered);
  stats.me_answer(2, MeAnswerResult::dropped_unknown);
  stats.me_answer(2, MeAnswerResult::dropped_other);
  stats.me_io(2, 1234, 5678);
  stats.me_last_answer_age(2, 9);
  stats.me_control(2, 5, 1, 2, 3);
  // Any non-contract DC is aggregated under the fixed "other" label.
  stats.me_queue(9999, 1, 1, 0, 0);

  const auto snapshot = stats.snapshot();
  ASSERT_EQ(snapshot.me_dcs.count("2"), 1u);
  const auto& dc = snapshot.me_dcs.at("2");
  EXPECT_EQ(dc.ready_queue_depth, 3u);
  EXPECT_EQ(dc.ready_queue_clients, 2u);
  EXPECT_EQ(dc.frames_queued_bytes, 4096u);
  EXPECT_EQ(dc.out_queued_bytes, 8192u);
  EXPECT_EQ(dc.proxy_ans_received_total, 2u);
  EXPECT_EQ(dc.proxy_ans_delivered_total, 1u);
  EXPECT_EQ(dc.proxy_ans_dropped_unknown_total, 1u);
  EXPECT_EQ(dc.proxy_ans_dropped_other_total, 1u);
  EXPECT_TRUE(dc.proxy_ans_seen);
  EXPECT_EQ(dc.last_proxy_ans_age_seconds, 9u);
  EXPECT_EQ(dc.rx_bytes_total, 1234u);
  EXPECT_EQ(dc.tx_bytes_total, 5678u);
  EXPECT_EQ(dc.control_close_conn, 5u);
  EXPECT_EQ(dc.control_close_ext, 1u);
  EXPECT_EQ(dc.control_unknown, 2u);
  EXPECT_EQ(dc.control_malformed, 3u);
  ASSERT_EQ(snapshot.me_dcs.count("other"), 1u);
  EXPECT_EQ(snapshot.me_dcs.at("other").ready_queue_depth, 1u);
  EXPECT_LE(snapshot.me_dcs.size(), 13u);

  const std::string text = stats.prometheus_text();
  EXPECT_NE(text.find("mtdd_me_ready_queue_depth{dc=\"2\"} 3\n"), std::string::npos);
  EXPECT_NE(text.find("mtdd_me_ready_queue_clients{dc=\"2\"} 2\n"),
            std::string::npos);
  EXPECT_NE(text.find("mtdd_me_frames_queued_bytes{dc=\"2\"} 4096\n"),
            std::string::npos);
  EXPECT_NE(text.find("mtdd_me_proxy_ans_total{dc=\"2\",result=\"received\"} 2\n"),
            std::string::npos);
  EXPECT_NE(text.find("mtdd_me_proxy_ans_total{dc=\"2\",result=\"delivered\"} 1\n"),
            std::string::npos);
  EXPECT_NE(
      text.find("mtdd_me_proxy_ans_dropped_total{dc=\"2\",reason=\"unknown_client\"} 1\n"),
      std::string::npos);
  EXPECT_NE(text.find("mtdd_me_proxy_ans_dropped_total{dc=\"2\",reason=\"other\"} 1\n"),
            std::string::npos);
  EXPECT_NE(text.find("mtdd_me_last_proxy_ans_age_seconds{dc=\"2\"} 9\n"),
            std::string::npos);
  EXPECT_NE(text.find("mtdd_me_rx_bytes_total{dc=\"2\"} 1234\n"), std::string::npos);
  EXPECT_NE(text.find("mtdd_me_tx_bytes_total{dc=\"2\"} 5678\n"), std::string::npos);
  EXPECT_NE(text.find("mtdd_me_control_frames{dc=\"2\",type=\"close_conn\"} 5\n"),
            std::string::npos);
  EXPECT_NE(text.find("mtdd_me_control_frames{dc=\"2\",type=\"close_ext\"} 1\n"),
            std::string::npos);
  EXPECT_NE(text.find("mtdd_me_control_frames{dc=\"2\",type=\"unknown\"} 2\n"),
            std::string::npos);
  EXPECT_NE(text.find("mtdd_me_control_frames{dc=\"2\",type=\"malformed\"} 3\n"),
            std::string::npos);
  EXPECT_EQ(text.find("127.0.0.1"), std::string::npos);
}

TEST(StatisticsTest, MeAnswerAgeIsWithdrawnWhenNoLiveConnectionAnswered) {
  Statistics stats;
  stats.me_last_answer_age(0, 2, 0);
  auto snapshot = stats.snapshot();
  ASSERT_EQ(snapshot.me_dcs.count("2"), 1u);
  EXPECT_TRUE(snapshot.me_dcs.at("2").proxy_ans_seen);
  EXPECT_EQ(snapshot.me_dcs.at("2").last_proxy_ans_age_seconds, 0u);
  EXPECT_NE(stats.prometheus_text().find(
                "mtdd_me_last_proxy_ans_age_seconds{dc=\"2\"} 0\n"),
            std::string::npos);

  // The pool was rotated and the replacement has not answered yet: withdraw the
  // series instead of freezing the last value of a connection that is gone.
  stats.me_last_answer_clear(0, 2);
  snapshot = stats.snapshot();
  EXPECT_FALSE(snapshot.me_dcs.at("2").proxy_ans_seen);
  EXPECT_EQ(snapshot.me_dcs.at("2").last_proxy_ans_age_seconds, 0u);
  EXPECT_EQ(stats.prometheus_text().find("mtdd_me_last_proxy_ans_age_seconds"),
            std::string::npos)
      << "a gauge without data must be absent, like the other ME gauges";

  // A later answer on a live replacement re-arms it.
  stats.me_last_answer_age(0, 2, 4);
  snapshot = stats.snapshot();
  EXPECT_TRUE(snapshot.me_dcs.at("2").proxy_ans_seen);
  EXPECT_EQ(snapshot.me_dcs.at("2").last_proxy_ans_age_seconds, 4u);
}

TEST(StatisticsTest, MeControlCountersSurviveConnectionReplacement) {
  Statistics stats;
  stats.me_connected(2, true);
  stats.me_control(2, 4, 1, 2, 3);
  auto snapshot = stats.snapshot();
  ASSERT_EQ(snapshot.me_dcs.count("2"), 1u);
  EXPECT_EQ(snapshot.me_dcs.at("2").control_close_conn, 4u);

  // A disconnect/reconnect transition must not erase the accumulated counters:
  // the reactor owns the per-DC base folded from replaced connections.
  stats.me_connected(2, false);
  snapshot = stats.snapshot();
  ASSERT_EQ(snapshot.me_dcs.count("2"), 1u);
  EXPECT_EQ(snapshot.me_dcs.at("2").control_close_conn, 4u);
  EXPECT_EQ(snapshot.me_dcs.at("2").control_close_ext, 1u);
  EXPECT_EQ(snapshot.me_dcs.at("2").control_unknown, 2u);
  EXPECT_EQ(snapshot.me_dcs.at("2").control_malformed, 3u);
  EXPECT_FALSE(snapshot.me_dcs.at("2").connected);
}

// Intersection of the multi-reactor statistics slots (workers) with the per-DC
// ME pool/keepalive gauges (melife): each reactor owns one pool, so pool sizes
// and ping counters add up, the connected flag is OR-ed, and the per-DC RTT
// gauge is the mean of the reactors that currently have a ready member.
TEST(StatisticsTest, MePoolAndKeepaliveAggregateAcrossReactors) {
  Statistics stats;
  stats.configure_workers(3);

  stats.me_connected(0, 2, true);
  stats.me_pool(0, 2, 2, 1);
  stats.me_ping_rtt(0, 2, 1'000);
  stats.me_ping_sent(2);
  stats.me_ping_sent(2);
  stats.me_ping_pong(2, 1'000);
  stats.me_ping_stall(2);
  stats.me_control(0, 2, 5, 1, 0, 0);

  stats.me_connected(1, 2, true);
  stats.me_pool(1, 2, 1, 1);
  stats.me_ping_rtt(1, 2, 3'000);
  stats.me_control(1, 2, 2, 0, 1, 0);

  // Reactor 2 has no ME connection for this DC and must not dilute the mean.
  stats.me_connected(2, 2, false);
  stats.me_pool(2, 2, 0, 0);

  auto snapshot = stats.snapshot();
  const auto& dc = snapshot.me_dcs.at("2");
  EXPECT_TRUE(dc.connected);
  EXPECT_EQ(dc.reactors_connected, 2u);
  EXPECT_EQ(dc.connections, 3u) << "pool sizes must add up across reactors";
  EXPECT_EQ(dc.ready_connections, 2u);
  EXPECT_EQ(dc.ping_rtt_us, 2'000u) << "the DC RTT is the mean of ready pools";
  EXPECT_EQ(dc.pings_sent_total, 2u);
  EXPECT_EQ(dc.pongs_received_total, 1u);
  EXPECT_EQ(dc.ping_stalls_total, 1u);
  EXPECT_EQ(dc.ping_timeouts_total, 0u);
  EXPECT_EQ(dc.control_close_conn, 7u);
  EXPECT_EQ(dc.control_close_ext, 1u);
  EXPECT_EQ(dc.control_unknown, 1u);

  const std::string text = stats.prometheus_text();
  // mtdd_me_connections is the ME socket count (workers-era meaning), the
  // reactor topology moved to mtdd_me_ready_reactors, and the intermediate
  // pool-split name stays as an alias.
  EXPECT_NE(text.find("mtdd_me_connections{dc=\"2\"} 3\n"), std::string::npos);
  EXPECT_NE(text.find("mtdd_me_ready_reactors{dc=\"2\"} 2\n"),
            std::string::npos);
  EXPECT_NE(text.find("mtdd_me_pool_connections{dc=\"2\"} 3\n"),
            std::string::npos);
  EXPECT_NE(text.find("mtdd_me_pool_ready{dc=\"2\"} 2\n"), std::string::npos);
  EXPECT_NE(text.find("mtdd_me_ping_rtt_us{dc=\"2\"} 2000\n"),
            std::string::npos);
  EXPECT_NE(text.find("mtdd_me_pings_total{dc=\"2\",result=\"sent\"} 2\n"),
            std::string::npos);
  EXPECT_NE(text.find("mtdd_me_pings_total{dc=\"2\",result=\"stalled\"} 1\n"),
            std::string::npos);

  // A disconnected reactor must not count as connected even when another one
  // still holds a ready pool.
  stats.me_connected(0, 2, false);
  stats.me_connected(1, 2, false);
  snapshot = stats.snapshot();
  EXPECT_FALSE(snapshot.me_dcs.at("2").connected);
  EXPECT_EQ(snapshot.me_dcs.at("2").reactors_connected, 0u);
  EXPECT_EQ(snapshot.me_dcs.at("2").connections, 3u)
      << "the pool gauge is owned by publish_me_pool, not by me_connected";
}

// Per-worker diagnostics must stay attributable to one reactor: the historical
// aggregate fields keep their summed meaning, and a locally exhausted worker is
// visible even when the other worker has slack.
TEST(StatisticsTest, WorkerDiagnosticsArePerWorkerNotSummed) {
  Statistics stats;
  stats.configure_workers(2);

  stats.set_worker_diagnostics(0, 64'000'000, 64U * 1024U * 1024U, 41, 3);
  stats.set_worker_diagnostics(1, 1'000'000, 64U * 1024U * 1024U, 7, 1);

  const auto snapshot = stats.snapshot();
  ASSERT_EQ(snapshot.workers.size(), 2u);
  EXPECT_EQ(snapshot.workers[0].budget_used_bytes, 64'000'000u);
  EXPECT_EQ(snapshot.workers[0].budget_limit_bytes, 64U * 1024U * 1024U);
  EXPECT_EQ(snapshot.workers[0].active_clients, 41u);
  EXPECT_EQ(snapshot.workers[0].handshakes_pending, 3u);
  EXPECT_EQ(snapshot.workers[1].budget_used_bytes, 1'000'000u);
  EXPECT_EQ(snapshot.workers[1].active_clients, 7u);
  // Backward compatibility: the existing aggregate is still the sum of the
  // per-worker gauges, not a second statistics system.
  EXPECT_EQ(snapshot.buffer_budget_used,
            snapshot.workers[0].budget_used_bytes +
                snapshot.workers[1].budget_used_bytes);
  EXPECT_EQ(snapshot.handshakes_pending, 4u);

  const std::string text = stats.prometheus_text();
  EXPECT_NE(text.find("mtdd_worker_budget_used_bytes{worker=\"0\"} 64000000\n"),
            std::string::npos);
  EXPECT_NE(text.find("mtdd_worker_budget_used_bytes{worker=\"1\"} 1000000\n"),
            std::string::npos);
  EXPECT_NE(text.find("mtdd_worker_budget_limit_bytes{worker=\"0\"} 67108864\n"),
            std::string::npos);
  EXPECT_NE(text.find("mtdd_worker_active_clients{worker=\"0\"} 41\n"),
            std::string::npos);
  EXPECT_NE(text.find("mtdd_worker_active_clients{worker=\"1\"} 7\n"),
            std::string::npos);
  // The legacy aggregate remains unchanged and unlabelled.
  EXPECT_NE(text.find("mtdd_buffer_budget_bytes 65000000\n"),
            std::string::npos);
}

TEST(StatisticsTest, MeWorkerDiagnosticsUseFixedWorkerAndDcLabels) {
  Statistics stats;
  stats.configure_workers(2);

  MeWorkerSnapshot worker0;
  worker0.connections = 6;
  worker0.ready_connections = 5;
  worker0.read_armed_connections = 3;
  worker0.budget_paused_connections = 2;
  worker0.bound_clients_on_paused = 11;
  worker0.budget_pauses_total = 7;
  worker0.budget_resumes_total = 6;
  worker0.current_pause_age_ms = 400;
  worker0.max_pause_age_ms = 900;
  stats.me_worker(0, 2, worker0);

  MeWorkerSnapshot worker1 = worker0;
  worker1.connections = 1;
  worker1.ready_connections = 1;
  worker1.read_armed_connections = 1;
  worker1.budget_paused_connections = 0;
  worker1.bound_clients_on_paused = 0;
  worker1.budget_pauses_total = 1;
  worker1.budget_resumes_total = 1;
  worker1.current_pause_age_ms = 0;
  worker1.max_pause_age_ms = 120;
  stats.me_worker(1, 2, worker1);
  // Any non-contract DC is aggregated under the fixed "other" label.
  stats.me_worker(0, 9999, worker0);

  const auto snapshot = stats.snapshot();
  ASSERT_EQ(snapshot.workers.size(), 2u);
  const auto& first = snapshot.workers[0].me_dcs.at("2");
  EXPECT_EQ(first.connections, 6u);
  EXPECT_EQ(first.read_armed_connections, 3u);
  EXPECT_EQ(first.budget_paused_connections, 2u);
  EXPECT_EQ(first.bound_clients_on_paused, 11u);
  EXPECT_EQ(first.budget_pauses_total, 7u);
  EXPECT_EQ(first.budget_resumes_total, 6u);
  EXPECT_EQ(first.current_pause_age_ms, 400u);
  EXPECT_EQ(first.max_pause_age_ms, 900u);
  const auto& second = snapshot.workers[1].me_dcs.at("2");
  EXPECT_EQ(second.budget_paused_connections, 0u);
  EXPECT_EQ(second.read_armed_connections, 1u);
  // The aggregate ME series is untouched: worker diagnostics are not summed
  // into it, and labels remain bounded.
  EXPECT_EQ(snapshot.me_dcs.at("2").bound_clients, 0u);
  EXPECT_LE(snapshot.workers[0].me_dcs.size(), 13u);
  EXPECT_EQ(snapshot.workers[0].me_dcs.count("9999"), 0u);
  ASSERT_EQ(snapshot.workers[0].me_dcs.count("other"), 1u);

  const std::string text = stats.prometheus_text();
  EXPECT_NE(text.find(
                "mtdd_worker_me_budget_paused{worker=\"0\",dc=\"2\"} 2\n"),
            std::string::npos);
  EXPECT_NE(text.find(
                "mtdd_worker_me_paused_bound_clients{worker=\"0\",dc=\"2\"} 11\n"),
            std::string::npos);
  EXPECT_NE(text.find("mtdd_worker_me_read_armed{worker=\"0\",dc=\"2\"} 3\n"),
            std::string::npos);
  EXPECT_NE(text.find(
                "mtdd_worker_me_budget_pauses_total{worker=\"0\",dc=\"2\"} 7\n"),
            std::string::npos);
  EXPECT_NE(text.find(
                "mtdd_worker_me_budget_resumes_total{worker=\"0\",dc=\"2\"} 6\n"),
            std::string::npos);
  EXPECT_NE(text.find(
                "mtdd_worker_me_pause_current_ms{worker=\"0\",dc=\"2\"} 400\n"),
            std::string::npos);
  EXPECT_NE(text.find(
                "mtdd_worker_me_pause_max_ms{worker=\"0\",dc=\"2\"} 900\n"),
            std::string::npos);
  EXPECT_NE(text.find("mtdd_worker_me_read_armed{worker=\"1\",dc=\"2\"} 1\n"),
            std::string::npos);
  EXPECT_NE(text.find("mtdd_worker_me_ready{worker=\"1\",dc=\"2\"} 1\n"),
            std::string::npos);
}

TEST(StatisticsTest, WorkerHeartbeatAndHousekeepingLatenessExposeStaleness) {
  Statistics stats;
  stats.configure_workers(2);
  const auto now_ns = static_cast<uint64_t>(
      std::chrono::duration_cast<std::chrono::nanoseconds>(
          std::chrono::steady_clock::now().time_since_epoch())
          .count());
  stats.set_worker_heartbeat_at(0, now_ns - 1'500'000'000ULL);
  stats.set_worker_heartbeat_at(1, now_ns);
  stats.set_worker_housekeeping_lateness(0, 12, 34);
  stats.set_worker_housekeeping_lateness(1, 0, 3);

  const auto snapshot = stats.snapshot();
  ASSERT_EQ(snapshot.workers.size(), 2u);
  EXPECT_TRUE(snapshot.workers[0].heartbeat_seen);
  EXPECT_GE(snapshot.workers[0].heartbeat_age_ms, 1'500u);
  EXPECT_TRUE(snapshot.workers[1].heartbeat_seen);
  EXPECT_LT(snapshot.workers[1].heartbeat_age_ms, 10'000u);
  EXPECT_EQ(snapshot.workers[0].housekeeping_lateness_ms, 12u);
  EXPECT_EQ(snapshot.workers[0].housekeeping_lateness_max_ms, 34u);
  EXPECT_EQ(snapshot.workers[1].housekeeping_lateness_max_ms, 3u);

  const std::string text = stats.prometheus_text();
  EXPECT_NE(text.find("mtdd_worker_heartbeat_age_ms{worker=\"0\"} "),
            std::string::npos);
  EXPECT_NE(text.find("mtdd_worker_housekeeping_lateness_ms{worker=\"0\"} 12\n"),
            std::string::npos);
  EXPECT_NE(
      text.find("mtdd_worker_housekeeping_lateness_max_ms{worker=\"0\"} 34\n"),
      std::string::npos);
  EXPECT_NE(text.find("mtdd_worker_housekeeping_lateness_ms{worker=\"1\"} 0\n"),
            std::string::npos);
}


}  // namespace

TEST(StatisticsTest, DirectFallbackSeriesUseBoundedDcLabels) {
  Statistics stats;
  stats.me_direct(2, 3, 10, 1, 1234, 5678);

  const auto snapshot = stats.snapshot();
  ASSERT_EQ(snapshot.me_dcs.count("2"), 1u);
  const auto& dc = snapshot.me_dcs.at("2");
  EXPECT_EQ(dc.direct_active, 3u);
  EXPECT_EQ(dc.direct_accepted_total, 10u);
  EXPECT_EQ(dc.direct_connect_fail_total, 1u);
  EXPECT_EQ(dc.direct_rx_bytes_total, 1234u);
  EXPECT_EQ(dc.direct_tx_bytes_total, 5678u);

  const std::string text = stats.prometheus_text();
  EXPECT_NE(text.find("mtdd_direct_active{dc=\"2\"} 3\n"), std::string::npos);
  EXPECT_NE(text.find("mtdd_direct_accepted_total{dc=\"2\"} 10\n"), std::string::npos);
  EXPECT_NE(text.find("mtdd_direct_connect_fail_total{dc=\"2\"} 1\n"), std::string::npos);
  EXPECT_NE(text.find("mtdd_direct_rx_bytes_total{dc=\"2\"} 1234\n"), std::string::npos);
  EXPECT_NE(text.find("mtdd_direct_tx_bytes_total{dc=\"2\"} 5678\n"), std::string::npos);

  // Any non-contract DC is aggregated under the fixed "other" label.
  stats.me_direct(9999, 1, 1, 0, 1, 1);
  const auto bounded = stats.snapshot();
  ASSERT_EQ(bounded.me_dcs.count("other"), 1u);
  EXPECT_EQ(bounded.me_dcs.at("other").direct_active, 1u);
  EXPECT_LE(bounded.me_dcs.size(), 13u);
}
