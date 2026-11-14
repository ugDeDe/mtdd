#include "../support/runtime_fixture.hpp"

// ---------------------------------------------------------------------------
// Per-user ad tag (UserPolicy::ad_tag): the user's ME requests carry it in
// place of the global tag.
// ---------------------------------------------------------------------------

TEST(UserAdTag, PersonalTagReplacesTheGlobalOneInMeRequests) {
    FakeMe me{me_secret()};
    Daemon daemon(me.port(), true);
    ASSERT_TRUE(daemon.services.add_user("alice", std::string(kSecretHex)));
    mtdd::control::UpdateUserRequest update;
    update.name = "alice";
    update.policy.ad_tag = std::string("C0C1C2C3C4C5C6C7C8C9CACBCCCDCECF");
    ASSERT_TRUE(daemon.services.store->update_user(update).ok());
    ASSERT_EQ(daemon.services.store->snapshot()->find("alice")->policy.ad_tag,
              "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf");
    ASSERT_TRUE(wait_for([&] { return daemon.services.metadata->snapshot() != nullptr; }, 3s));
    ASSERT_TRUE(wait_for([&] { return daemon.services.stats.ready(); }, 3s));

    TestClient client(daemon.port(), secret_bytes());
    ASSERT_TRUE(client.valid());
    ASSERT_TRUE(client.send_hello());
    ASSERT_TRUE(client.start_obfuscation(2));
    ASSERT_TRUE(client.send_message(burst_payload(0)));
    ASSERT_EQ(me.future().wait_for(5s), std::future_status::ready);
    const auto observation = me.future().get();
    ASSERT_TRUE(observation.ok);
    std::array<std::uint8_t, 16> expected{};
    for (std::size_t i = 0; i < expected.size(); ++i) expected[i] = static_cast<std::uint8_t>(0xc0 + i);
    EXPECT_EQ(observation.ad_tag, expected);
}

TEST(UserAdTag, InvalidTagsAreRefusedByTheStore) {
    Services services(1, false);
    ASSERT_TRUE(services.add_user("alice", std::string(kSecretHex)));
    for (const char* bad : {"00000000000000000000000000000000", "zz112233445566778899aabbccddeeff",
                            "0011", "00112233445566778899aabbccddeeff00"}) {
        SCOPED_TRACE(bad);
        mtdd::control::UpdateUserRequest update;
        update.name = "alice";
        update.policy.ad_tag = std::string(bad);
        EXPECT_FALSE(services.store->update_user(update).ok());
    }
    mtdd::control::UpdateUserRequest clear;
    clear.name = "alice";
    clear.policy.ad_tag = std::string("00112233445566778899aabbccddeeff");
    ASSERT_TRUE(services.store->update_user(clear).ok());
    clear.policy.ad_tag = std::string();
    ASSERT_TRUE(services.store->update_user(clear).ok());
    EXPECT_TRUE(services.store->snapshot()->find("alice")->policy.ad_tag.empty());
}

// A proxy configured without an ad tag relays through ME, and the middle end
// receives RPC_PROXY_REQ with no TL_PROXY_TAG block (all-zero observed tag).
TEST(UserAdTag, NoGlobalTagRelaysWithoutTheProxyTag) {
    FakeMe me{me_secret()};
    Daemon daemon(me.port(), true, [](mtdd::Config& config) { config.ad_tag.fill(0); });
    ASSERT_TRUE(daemon.services.add_user("alice", std::string(kSecretHex)));
    ASSERT_TRUE(wait_for([&] { return daemon.services.metadata->snapshot() != nullptr; }, 3s));
    ASSERT_TRUE(wait_for([&] { return daemon.services.stats.ready(); }, 3s));

    TestClient client(daemon.port(), secret_bytes());
    ASSERT_TRUE(client.valid());
    ASSERT_TRUE(client.send_hello());
    ASSERT_TRUE(client.start_obfuscation(2));
    const Bytes request = burst_payload(0);
    ASSERT_TRUE(client.send_message(request));
    ASSERT_EQ(me.future().wait_for(5s), std::future_status::ready);
    const auto observation = me.future().get();
    ASSERT_TRUE(observation.ok);
    EXPECT_EQ(observation.inner, request);
    // No tag block: the observed ad tag is all-zero.
    EXPECT_TRUE(std::all_of(observation.ad_tag.begin(), observation.ad_tag.end(),
                            [](std::uint8_t b) { return b == 0; }));
    Bytes response;
    ASSERT_TRUE(client.read_message(response));
    EXPECT_EQ(response, (Bytes{0xaa, 0xbb, 0xcc, 0xdd, 0x11, 0x22, 0x33, 0x44}));
}
