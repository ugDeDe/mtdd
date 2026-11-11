#include "../support/control_fixture.hpp"

namespace {

TEST(UserStoreTest, OpenMissingFileStartsEmptyAtRevisionZero) {
  TempDir dir;
  auto store = open_store_or_throw(dir.file("state/users.json"));
  auto snapshot = store.snapshot();
  ASSERT_NE(snapshot, nullptr);
  EXPECT_EQ(snapshot->revision, 0u);
  EXPECT_TRUE(snapshot->users.empty());
  EXPECT_EQ(store.path(), dir.file("state/users.json"));
  EXPECT_EQ(mode_of(dir.file("state")), 0700u);
}

TEST(UserStoreTest, CreateGeneratesValidSecretAndPublishes) {
  TempDir dir;
  auto store = open_store_or_throw(dir.file("users.json"));

  CreateUserRequest request;
  request.name = "alice";
  auto result = store.create_user(request);
  ASSERT_TRUE(result.ok()) << result.error().message;
  const MutationOutcome& outcome = result.value();
  EXPECT_EQ(outcome.revision, 1u);
  EXPECT_TRUE(outcome.applied);
  EXPECT_FALSE(outcome.pending);
  ASSERT_TRUE(outcome.secret_once.has_value());
  EXPECT_EQ(outcome.secret_once->size(), 32u);
  EXPECT_TRUE(UserStore::is_valid_secret_hex(*outcome.secret_once));
  EXPECT_EQ(outcome.secret_once->find_first_not_of("0123456789abcdef"),
            std::string::npos);

  auto snapshot = store.snapshot();
  ASSERT_EQ(snapshot->users.size(), 1u);
  EXPECT_EQ(snapshot->users[0].name, "alice");
  EXPECT_EQ(snapshot->users[0].secret_hex, *outcome.secret_once);
  EXPECT_TRUE(snapshot->users[0].enabled);
  EXPECT_FALSE(snapshot->users[0].max_connections.has_value());
  EXPECT_EQ(snapshot->users[0].generation, 1u);
  EXPECT_EQ(snapshot->revision, 1u);
  ASSERT_NE(snapshot->find("alice"), nullptr);
  EXPECT_EQ(snapshot->find("nobody"), nullptr);
}

TEST(UserStoreTest, SuppliedSecretIsNormalizedAndValidated) {
  TempDir dir;
  auto store = open_store_or_throw(dir.file("users.json"));
  CreateUserRequest request;
  request.name = "alice";
  request.secret = "AABBCCDDEEFF00112233445566778899";
  auto result = store.create_user(request);
  ASSERT_TRUE(result.ok()) << result.error().message;
  EXPECT_EQ(result.value().secret_once.value(), "aabbccddeeff00112233445566778899");
  ASSERT_NE(store.snapshot()->find("alice"), nullptr);
  EXPECT_EQ(store.snapshot()->find("alice")->secret_hex,
            "aabbccddeeff00112233445566778899");
}

TEST(UserStoreTest, RejectsInvalidNames) {
  TempDir dir;
  auto store = open_store_or_throw(dir.file("users.json"));
  const std::vector<std::string> bad = {
      "", "has space", "slash/name", "name?", std::string(65, 'a'), "ümlaut"};
  for (const auto& name : bad) {
    CreateUserRequest request;
    request.name = name;
    auto result = store.create_user(request);
    ASSERT_FALSE(result.ok()) << "name should be rejected: " << name;
    EXPECT_EQ(result.error().code, ErrorCode::invalid_name) << name;
  }
  EXPECT_EQ(store.snapshot()->revision, 0u);
  EXPECT_TRUE(store.snapshot()->users.empty());
}

TEST(UserStoreTest, RejectsInvalidSecrets) {
  TempDir dir;
  auto store = open_store_or_throw(dir.file("users.json"));
  const std::vector<std::string> bad = {
      "", "abc", std::string(31, 'a'), std::string(33, 'a'), std::string(32, 'z'),
      "00112233445566778899aabbccddeefg", "0011 2233445566778899aabbccddeeff"};
  for (const auto& secret : bad) {
    CreateUserRequest request;
    request.name = "alice";
    request.secret = secret;
    auto result = store.create_user(request);
    ASSERT_FALSE(result.ok()) << "secret should be rejected: " << secret;
    EXPECT_EQ(result.error().code, ErrorCode::invalid_secret) << secret;
  }
  EXPECT_TRUE(store.snapshot()->users.empty());
}

TEST(UserStoreTest, RejectsDuplicateNameAndSecret) {
  TempDir dir;
  auto store = open_store_or_throw(dir.file("users.json"));
  CreateUserRequest first;
  first.name = "alice";
  first.secret = kHexA;
  ASSERT_TRUE(store.create_user(first).ok());

  CreateUserRequest duplicate_name;
  duplicate_name.name = "alice";
  auto name_result = store.create_user(duplicate_name);
  ASSERT_FALSE(name_result.ok());
  EXPECT_EQ(name_result.error().code, ErrorCode::duplicate_name);

  CreateUserRequest duplicate_secret;
  duplicate_secret.name = "bob";
  duplicate_secret.secret = kHexA;
  auto secret_result = store.create_user(duplicate_secret);
  ASSERT_FALSE(secret_result.ok());
  EXPECT_EQ(secret_result.error().code, ErrorCode::duplicate_secret);

  EXPECT_EQ(store.snapshot()->revision, 1u);
  EXPECT_EQ(store.snapshot()->users.size(), 1u);
}

TEST(UserStoreTest, ValidatesMaxConnectionsBoundsAndNullSemantics) {
  TempDir dir;
  auto store = open_store_or_throw(dir.file("users.json"));
  for (uint32_t bad : {0u, 1000001u}) {
    CreateUserRequest request;
    request.name = "alice";
    request.max_connections = bad;
    auto result = store.create_user(request);
    ASSERT_FALSE(result.ok());
    EXPECT_EQ(result.error().code, ErrorCode::invalid_field);
  }

  CreateUserRequest limited;
  limited.name = "alice";
  limited.max_connections = 3;
  ASSERT_TRUE(store.create_user(limited).ok());
  EXPECT_EQ(store.snapshot()->find("alice")->max_connections.value(), 3u);

  UpdateUserRequest clear;
  clear.name = "alice";
  clear.set_max_connections = true;
  clear.max_connections = std::nullopt;
  auto cleared = store.update_user(clear);
  ASSERT_TRUE(cleared.ok()) << cleared.error().message;
  EXPECT_FALSE(store.snapshot()->find("alice")->max_connections.has_value());
}

TEST(UserStoreTest, DisableAndRotateBumpGenerationButEnableAndCapDoNot) {
  TempDir dir;
  auto store = open_store_or_throw(dir.file("users.json"));
  CreateUserRequest create;
  create.name = "alice";
  create.secret = kHexA;
  ASSERT_TRUE(store.create_user(create).ok());
  ASSERT_EQ(store.snapshot()->find("alice")->generation, 1u);

  UpdateUserRequest disable;
  disable.name = "alice";
  disable.enabled = false;
  auto disabled = store.update_user(disable);
  ASSERT_TRUE(disabled.ok()) << disabled.error().message;
  EXPECT_EQ(disabled.value().user.generation, 2u);
  EXPECT_FALSE(disabled.value().user.enabled);

  UpdateUserRequest enable;
  enable.name = "alice";
  enable.enabled = true;
  auto enabled = store.update_user(enable);
  ASSERT_TRUE(enabled.ok()) << enabled.error().message;
  EXPECT_EQ(enabled.value().user.generation, 2u);

  UpdateUserRequest cap;
  cap.name = "alice";
  cap.set_max_connections = true;
  cap.max_connections = 10;
  auto capped = store.update_user(cap);
  ASSERT_TRUE(capped.ok()) << capped.error().message;
  EXPECT_EQ(capped.value().user.generation, 2u);

  RotateSecretRequest rotate;
  rotate.name = "alice";
  auto rotated = store.rotate_secret(rotate);
  ASSERT_TRUE(rotated.ok()) << rotated.error().message;
  // Generation is allocated from the new persisted revision (rev 4).
  EXPECT_EQ(rotated.value().user.generation, 5u);
  ASSERT_TRUE(rotated.value().secret_once.has_value());
  EXPECT_NE(rotated.value().secret_once.value(), kHexA);
  EXPECT_EQ(store.snapshot()->find("alice")->secret_hex,
            rotated.value().secret_once.value());

  RotateSecretRequest supplied;
  supplied.name = "alice";
  supplied.secret = kHexB;
  auto supplied_result = store.rotate_secret(supplied);
  ASSERT_TRUE(supplied_result.ok()) << supplied_result.error().message;
  EXPECT_EQ(supplied_result.value().secret_once.value(), kHexB);
  EXPECT_EQ(supplied_result.value().user.generation, 6u);
}

TEST(UserStoreTest, RotateRejectsSecretInUseByOtherUser) {
  TempDir dir;
  auto store = open_store_or_throw(dir.file("users.json"));
  CreateUserRequest alice;
  alice.name = "alice";
  alice.secret = kHexA;
  ASSERT_TRUE(store.create_user(alice).ok());
  CreateUserRequest bob;
  bob.name = "bob";
  bob.secret = kHexB;
  ASSERT_TRUE(store.create_user(bob).ok());

  RotateSecretRequest rotate;
  rotate.name = "alice";
  rotate.secret = kHexB;
  auto result = store.rotate_secret(rotate);
  ASSERT_FALSE(result.ok());
  EXPECT_EQ(result.error().code, ErrorCode::duplicate_secret);
  EXPECT_EQ(store.snapshot()->find("alice")->secret_hex, kHexA);
  EXPECT_EQ(store.snapshot()->find("alice")->generation, 1u);
}

TEST(UserStoreTest, UpdateAndDeleteMissingUserReturnNotFound) {
  TempDir dir;
  auto store = open_store_or_throw(dir.file("users.json"));
  UpdateUserRequest update;
  update.name = "ghost";
  update.enabled = false;
  auto update_result = store.update_user(update);
  ASSERT_FALSE(update_result.ok());
  EXPECT_EQ(update_result.error().code, ErrorCode::not_found);

  DeleteUserRequest remove;
  remove.name = "ghost";
  auto delete_result = store.delete_user(remove);
  ASSERT_FALSE(delete_result.ok());
  EXPECT_EQ(delete_result.error().code, ErrorCode::not_found);

  RotateSecretRequest rotate;
  rotate.name = "ghost";
  auto rotate_result = store.rotate_secret(rotate);
  ASSERT_FALSE(rotate_result.ok());
  EXPECT_EQ(rotate_result.error().code, ErrorCode::not_found);
  EXPECT_EQ(store.snapshot()->revision, 0u);
}

TEST(UserStoreTest, UpdateRequiresAtLeastOneField) {
  TempDir dir;
  auto store = open_store_or_throw(dir.file("users.json"));
  CreateUserRequest create;
  create.name = "alice";
  ASSERT_TRUE(store.create_user(create).ok());

  UpdateUserRequest empty;
  empty.name = "alice";
  auto result = store.update_user(empty);
  ASSERT_FALSE(result.ok());
  EXPECT_EQ(result.error().code, ErrorCode::invalid_request);
  EXPECT_EQ(store.snapshot()->revision, 1u);
}

TEST(UserStoreTest, DeleteRemovesRecordAndPersists) {
  TempDir dir;
  auto store = open_store_or_throw(dir.file("users.json"));
  CreateUserRequest create;
  create.name = "alice";
  ASSERT_TRUE(store.create_user(create).ok());
  DeleteUserRequest remove;
  remove.name = "alice";
  auto result = store.delete_user(remove);
  ASSERT_TRUE(result.ok()) << result.error().message;
  EXPECT_TRUE(result.value().deleted);
  EXPECT_EQ(result.value().revision, 2u);
  EXPECT_TRUE(store.snapshot()->users.empty());
  EXPECT_EQ(store.snapshot()->revision, 2u);

  auto reopened = open_store_or_throw(dir.file("users.json"));
  EXPECT_TRUE(reopened.snapshot()->users.empty());
  EXPECT_EQ(reopened.snapshot()->revision, 2u);
}

TEST(UserStoreTest, DeleteAndRecreateNeverReusesAuthGeneration) {
  TempDir dir;
  auto store = open_store_or_throw(dir.file("users.json"));
  CreateUserRequest create;
  create.name = "alice";
  ASSERT_TRUE(store.create_user(create).ok());
  const uint64_t first_generation = store.snapshot()->find("alice")->generation;
  EXPECT_EQ(first_generation, 1u);

  DeleteUserRequest remove;
  remove.name = "alice";
  ASSERT_TRUE(store.delete_user(remove).ok());
  ASSERT_EQ(store.snapshot()->revision, 2u);

  CreateUserRequest recreate;
  recreate.name = "alice";
  auto recreated = store.create_user(recreate);
  ASSERT_TRUE(recreated.ok()) << recreated.error().message;
  const uint64_t second_generation = recreated.value().user.generation;
  // A live session carrying {alice, first_generation} must never match the
  // recreated record, even though the name is identical.
  EXPECT_GT(second_generation, first_generation);
  EXPECT_NE(second_generation, first_generation);
  EXPECT_EQ(second_generation, 3u);
  EXPECT_EQ(store.snapshot()->revision, second_generation);

  // Disabling allocates a fresh revision-based generation as well.
  UpdateUserRequest disable;
  disable.name = "alice";
  disable.enabled = false;
  auto disabled = store.update_user(disable);
  ASSERT_TRUE(disabled.ok()) << disabled.error().message;
  EXPECT_EQ(disabled.value().user.generation, 4u);
  EXPECT_NE(disabled.value().user.generation, second_generation);

  auto reopened = open_store_or_throw(dir.file("users.json"));
  ASSERT_NE(reopened.snapshot()->find("alice"), nullptr);
  EXPECT_EQ(reopened.snapshot()->find("alice")->generation, 4u);
}

// ---------------------------------------------------------------------------
// UserStore: persistence, permissions, failures, symlinks
// ---------------------------------------------------------------------------

TEST(UserStorePersistenceTest, RestartRestoresRevisionUsersAndSecrets) {
  TempDir dir;
  std::string secret;
  {
    auto store = open_store_or_throw(dir.file("users.json"));
    CreateUserRequest alice;
    alice.name = "alice";
    alice.enabled = false;
    alice.max_connections = 7;
    auto created = store.create_user(alice);
    ASSERT_TRUE(created.ok()) << created.error().message;
    secret = created.value().secret_once.value();
    CreateUserRequest bob;
    bob.name = "bob";
    bob.secret = kHexB;
    ASSERT_TRUE(store.create_user(bob).ok());
    RotateSecretRequest rotate;
    rotate.name = "bob";
    ASSERT_TRUE(store.rotate_secret(rotate).ok());
    EXPECT_EQ(store.snapshot()->revision, 3u);
  }
  auto store = open_store_or_throw(dir.file("users.json"));
  auto snapshot = store.snapshot();
  ASSERT_EQ(snapshot->revision, 3u);
  ASSERT_EQ(snapshot->users.size(), 2u);
  ASSERT_NE(snapshot->find("alice"), nullptr);
  EXPECT_EQ(snapshot->find("alice")->secret_hex, secret);
  EXPECT_FALSE(snapshot->find("alice")->enabled);
  EXPECT_EQ(snapshot->find("alice")->max_connections.value(), 7u);
  ASSERT_NE(snapshot->find("bob"), nullptr);
  EXPECT_EQ(snapshot->find("bob")->generation, 3u);
}

TEST(UserStorePersistenceTest, FileSchemaIsStableJson) {
  TempDir dir;
  auto store = open_store_or_throw(dir.file("users.json"));
  CreateUserRequest request;
  request.name = "alice";
  request.secret = kHexA;
  request.max_connections = 2;
  ASSERT_TRUE(store.create_user(request).ok());

  auto j = nlohmann::json::parse(read_text_file(dir.file("users.json")));
  EXPECT_EQ(j["version"], 1);
  EXPECT_EQ(j["revision"], 1);
  ASSERT_TRUE(j["users"].is_array());
  ASSERT_EQ(j["users"].size(), 1u);
  EXPECT_EQ(j["users"][0]["name"], "alice");
  EXPECT_EQ(j["users"][0]["secret"], kHexA);
  EXPECT_EQ(j["users"][0]["enabled"], true);
  EXPECT_EQ(j["users"][0]["max_connections"], 2);
  EXPECT_EQ(j["users"][0]["generation"], 1);
}

TEST(UserStorePersistenceTest, FilesAndCreatedDirectoriesAreRestrictive) {
  TempDir dir;
  const std::string state_dir = dir.file("private/state");
  auto store = open_store_or_throw(state_dir + "/users.json");
  CreateUserRequest request;
  request.name = "alice";
  ASSERT_TRUE(store.create_user(request).ok());
  EXPECT_EQ(mode_of(state_dir), 0700u);
  EXPECT_EQ(mode_of(state_dir + "/users.json"), 0600u);
  EXPECT_EQ(mode_of(dir.file("private")), 0700u);
}

TEST(UserStorePersistenceTest, RejectsGroupOrWorldAccessibleExistingFile) {
  const std::string valid =
      R"({"version":1,"revision":1,"users":[{"name":"alice","secret":"00112233445566778899aabbccddeeff","enabled":true,"max_connections":null,"generation":1}]})";
  for (mode_t mode : {mode_t{0644}, mode_t{0640}, mode_t{0604}, mode_t{0666}}) {
    TempDir dir;
    const std::string path = dir.file("users.json");
    write_text_file(path, valid, mode);
    auto result = UserStore::open(path);
    ASSERT_FALSE(result.ok()) << "mode " << std::oct << mode;
    EXPECT_EQ(result.error().code, ErrorCode::permission_denied);
    // Fail closed: the operator file must not be silently chmod'ed or read.
    EXPECT_EQ(mode_of(path), static_cast<mode_t>(mode));
  }
}

TEST(UserStorePersistenceTest, RejectsFileOwnedByAnotherUserWhenPrivileged) {
  if (::geteuid() != 0) GTEST_SKIP() << "chown to another owner requires root";
  TempDir dir;
  const std::string path = dir.file("users.json");
  write_text_file(
      path,
      R"({"version":1,"revision":1,"users":[{"name":"alice","secret":"00112233445566778899aabbccddeeff","enabled":true,"max_connections":null,"generation":1}]})");
  ASSERT_EQ(::chown(path.c_str(), 65534, 65534), 0);
  auto result = UserStore::open(path);
  ASSERT_FALSE(result.ok());
  EXPECT_EQ(result.error().code, ErrorCode::permission_denied);
}

TEST(UserStorePersistenceTest, WriteFailureDoesNotPublishOrAdvanceRevision) {
  if (::geteuid() == 0) GTEST_SKIP() << "permission checks are bypassed as root";
  TempDir dir;
  const std::string state_dir = dir.file("state");
  auto store = open_store_or_throw(state_dir + "/users.json");
  ASSERT_EQ(::chmod(state_dir.c_str(), 0500), 0);

  CreateUserRequest request;
  request.name = "alice";
  auto result = store.create_user(request);
  ASSERT_FALSE(result.ok());
  EXPECT_TRUE(result.error().code == ErrorCode::permission_denied ||
              result.error().code == ErrorCode::io_error);
  EXPECT_EQ(store.snapshot()->revision, 0u);
  EXPECT_TRUE(store.snapshot()->users.empty());

  ASSERT_EQ(::chmod(state_dir.c_str(), 0700), 0);
  auto retry = store.create_user(request);
  ASSERT_TRUE(retry.ok()) << retry.error().message;
  EXPECT_EQ(store.snapshot()->revision, 1u);
}

TEST(UserStorePersistenceTest, RejectsSymlinkTargetOnOpen) {
  TempDir dir;
  const std::string target = dir.file("real.json");
  write_text_file(target, R"({"version":1,"revision":0,"users":[]})");
  const std::string link = dir.file("users.json");
  ASSERT_EQ(::symlink(target.c_str(), link.c_str()), 0);
  auto result = UserStore::open(link);
  ASSERT_FALSE(result.ok());
  EXPECT_EQ(result.error().code, ErrorCode::symlink_rejected);
}

TEST(UserStorePersistenceTest, RejectsSymlinkTargetOnWrite) {
  TempDir dir;
  const std::string target = dir.file("attacker.json");
  write_text_file(target, "untouched");
  const std::string path = dir.file("users.json");
  auto store = open_store_or_throw(path);
  ASSERT_EQ(::symlink(target.c_str(), path.c_str()), 0);

  CreateUserRequest request;
  request.name = "alice";
  auto result = store.create_user(request);
  ASSERT_FALSE(result.ok());
  EXPECT_EQ(result.error().code, ErrorCode::symlink_rejected);
  EXPECT_EQ(read_text_file(target), "untouched");
  EXPECT_EQ(store.snapshot()->revision, 0u);
}

TEST(UserStorePersistenceTest, EnforcesMaxUsers) {
  TempDir dir;
  StoreOptions options;
  options.max_users = 2;
  auto store = open_store_or_throw(dir.file("users.json"), options);
  for (const char* name : {"one", "two"}) {
    CreateUserRequest request;
    request.name = name;
    ASSERT_TRUE(store.create_user(request).ok());
  }
  CreateUserRequest third;
  third.name = "three";
  auto result = store.create_user(third);
  ASSERT_FALSE(result.ok());
  EXPECT_EQ(result.error().code, ErrorCode::limit_exceeded);
  EXPECT_EQ(store.snapshot()->revision, 2u);
  EXPECT_EQ(store.snapshot()->users.size(), 2u);
}

TEST(UserStorePersistenceTest, EnforcesMaxFileBytesOnWriteAndLoad) {
  TempDir dir;
  StoreOptions options;
  options.max_file_bytes = 128;
  auto store = open_store_or_throw(dir.file("users.json"), options);
  CreateUserRequest request;
  request.name = "alice";
  auto result = store.create_user(request);
  ASSERT_FALSE(result.ok());
  EXPECT_EQ(result.error().code, ErrorCode::file_too_large);
  EXPECT_EQ(store.snapshot()->revision, 0u);

  TempDir other;
  write_text_file(other.file("users.json"), std::string(200, ' '));
  auto loaded = UserStore::open(other.file("users.json"), options);
  ASSERT_FALSE(loaded.ok());
  EXPECT_EQ(loaded.error().code, ErrorCode::file_too_large);
}

TEST(UserStorePersistenceTest, RejectsMalformedOrInvalidFile) {
  TempDir dir;
  write_text_file(dir.file("malformed.json"), "{not json");
  auto malformed = UserStore::open(dir.file("malformed.json"));
  ASSERT_FALSE(malformed.ok());
  EXPECT_EQ(malformed.error().code, ErrorCode::invalid_json);

  write_text_file(dir.file("version.json"),
                  R"({"version":3,"revision":0,"users":[]})");
  auto version = UserStore::open(dir.file("version.json"));
  ASSERT_FALSE(version.ok());
  EXPECT_EQ(version.error().code, ErrorCode::unsupported_version);

  write_text_file(dir.file("unknown.json"),
                  R"({"version":1,"revision":0,"users":[],"extra":true})");
  auto unknown = UserStore::open(dir.file("unknown.json"));
  ASSERT_FALSE(unknown.ok());
  EXPECT_EQ(unknown.error().code, ErrorCode::unknown_field);

  write_text_file(
      dir.file("dup.json"),
      R"({"version":1,"revision":0,"users":[)"
      R"({"name":"a","secret":"00112233445566778899aabbccddeeff","enabled":true,"max_connections":null,"generation":1},)"
      R"({"name":"a","secret":"ffeeddccbbaa99887766554433221100","enabled":true,"max_connections":null,"generation":1}]})");
  auto duplicate = UserStore::open(dir.file("dup.json"));
  ASSERT_FALSE(duplicate.ok());
  EXPECT_EQ(duplicate.error().code, ErrorCode::duplicate_name);

  write_text_file(
      dir.file("baduser.json"),
      R"({"version":1,"revision":0,"users":[{"name":"a","secret":"short","enabled":true,"max_connections":null,"generation":1}]})");
  auto bad_user = UserStore::open(dir.file("baduser.json"));
  ASSERT_FALSE(bad_user.ok());
  EXPECT_EQ(bad_user.error().code, ErrorCode::invalid_secret);

  write_text_file(
      dir.file("unknownuser.json"),
      R"({"version":1,"revision":0,"users":[{"name":"a","secret":"00112233445566778899aabbccddeeff","enabled":true,"max_connections":null,"generation":1,"quota":2}]})");
  auto unknown_user = UserStore::open(dir.file("unknownuser.json"));
  ASSERT_FALSE(unknown_user.ok());
  EXPECT_EQ(unknown_user.error().code, ErrorCode::unknown_field);
}

TEST(UserStorePersistenceTest, RejectsGenerationNewerThanRevision) {
  TempDir dir;
  write_text_file(
      dir.file("users.json"),
      R"({"version":1,"revision":1,"users":[{"name":"a","secret":"00112233445566778899aabbccddeeff","enabled":true,"max_connections":null,"generation":2}]})");
  auto result = UserStore::open(dir.file("users.json"));
  ASSERT_FALSE(result.ok());
  EXPECT_EQ(result.error().code, ErrorCode::invalid_file);
}

TEST(UserStorePersistenceTest, PostRenameUncertaintyLatchesMutationsUntilRestart) {
  if (::geteuid() == 0) GTEST_SKIP() << "directory permissions are bypassed as root";
  TempDir dir;
  const std::string state_dir = dir.file("state");
  const std::string path = state_dir + "/users.json";
  auto store = open_store_or_throw(path);
  ASSERT_EQ(::chmod(state_dir.c_str(), 0300), 0);

  CreateUserRequest first;
  first.name = "alice";
  auto uncertain = store.create_user(first);
  ASSERT_EQ(::chmod(state_dir.c_str(), 0700), 0);
  ASSERT_FALSE(uncertain.ok());
  EXPECT_TRUE(uncertain.error().code == ErrorCode::permission_denied ||
              uncertain.error().code == ErrorCode::io_error);
  EXPECT_TRUE(uncertain.error().uncertain);
  // In-memory state was not published from the uncertain write.
  EXPECT_EQ(store.snapshot()->revision, 0u);
  EXPECT_TRUE(store.snapshot()->users.empty());

  CreateUserRequest second;
  second.name = "bob";
  auto latched = store.create_user(second);
  ASSERT_FALSE(latched.ok());
  EXPECT_EQ(latched.error().code, ErrorCode::io_error);
  EXPECT_NE(latched.error().message.find("restart"), std::string::npos);
  EXPECT_EQ(store.snapshot()->revision, 0u);

  // The durable file already contains the uncertain revision; restart exposes it.
  auto reopened = open_store_or_throw(path);
  EXPECT_EQ(reopened.snapshot()->revision, 1u);
  ASSERT_NE(reopened.snapshot()->find("alice"), nullptr);
  EXPECT_EQ(reopened.snapshot()->find("bob"), nullptr);
}

TEST(UserStorePersistenceTest, IfMatchProtectsMutations) {
  TempDir dir;
  auto store = open_store_or_throw(dir.file("users.json"));
  CreateUserRequest create;
  create.name = "alice";
  ASSERT_TRUE(store.create_user(create).ok());

  UpdateUserRequest stale;
  stale.name = "alice";
  stale.enabled = false;
  stale.if_match = 99;
  auto stale_result = store.update_user(stale);
  ASSERT_FALSE(stale_result.ok());
  EXPECT_EQ(stale_result.error().code, ErrorCode::revision_conflict);
  EXPECT_TRUE(store.snapshot()->find("alice")->enabled);
  EXPECT_EQ(store.snapshot()->revision, 1u);

  UpdateUserRequest current;
  current.name = "alice";
  current.enabled = false;
  current.if_match = 1;
  auto current_result = store.update_user(current);
  ASSERT_TRUE(current_result.ok()) << current_result.error().message;
  EXPECT_EQ(current_result.value().revision, 2u);
  EXPECT_FALSE(store.snapshot()->find("alice")->enabled);
}

// ---------------------------------------------------------------------------
// UserStore: snapshot publication is independent of durable persistence
// ---------------------------------------------------------------------------


}  // namespace
