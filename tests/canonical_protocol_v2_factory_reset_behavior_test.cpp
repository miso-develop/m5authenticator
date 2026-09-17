#include <algorithm>
#include <array>
#include <cassert>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "cJSON.h"
#include "m5auth/core/metadata.hpp"
#include "m5auth/provisioning/canonical_protocol_v2.hpp"
#include "m5auth/provisioning/canonical_v2_state.hpp"
#include "m5auth/provisioning/session_protocol_v2.hpp"
#include "m5auth/session/protocol_v2.hpp"
#include "m5auth/session/session.hpp"
#include "m5auth/time/time_service.hpp"
#include "m5auth/vault.hpp"
#include "m5auth/vault_runtime/runtime.hpp"

namespace {

template <std::size_t N>
std::array<std::uint8_t, N> sequence(std::uint8_t start) {
    std::array<std::uint8_t, N> result{};
    for (std::size_t index = 0; index < N; ++index) {
        result[index] = static_cast<std::uint8_t>(start + index);
    }
    return result;
}

struct RegistrationModel {
    m5auth::registration::Snapshot snapshot{};
    m5auth::registration::Status snapshot_status{m5auth::registration::Status::kOk};
    m5auth::registration::Status clear_result{m5auth::registration::Status::kOk};
    int clear_calls{0};
};

RegistrationModel* g_registration_model = nullptr;
std::uint8_t g_random_seed = 1;

class FakePersistence final : public m5auth::vault_runtime::Persistence {
public:
    m5auth::vault_runtime::Status load(
        m5auth::vault_runtime::PersistedSnapshot* output
    ) override {
        if (output == nullptr) return m5auth::vault_runtime::Status::kInvalidArgument;
        *output = snapshot;
        return snapshot.schema_ready
            ? m5auth::vault_runtime::Status::kOk
            : m5auth::vault_runtime::Status::kUnprovisioned;
    }

    m5auth::vault_runtime::Status format_schema2() override {
        snapshot = {};
        snapshot.schema_ready = true;
        return m5auth::vault_runtime::Status::kOk;
    }

    m5auth::vault_runtime::Status replace_envelope(
        std::uint64_t expected_generation,
        const m5auth::vault::VaultEnvelope& envelope
    ) override {
        if (expected_generation == 0) {
            if (snapshot.has_vault) return m5auth::vault_runtime::Status::kGenerationMismatch;
        } else if (!snapshot.has_vault ||
                   snapshot.envelope.generation != expected_generation ||
                   envelope.generation != expected_generation + 1 ||
                   envelope.vault_id != snapshot.envelope.vault_id) {
            return m5auth::vault_runtime::Status::kGenerationMismatch;
        }
        snapshot.schema_ready = true;
        snapshot.has_vault = true;
        snapshot.envelope = envelope;
        return m5auth::vault_runtime::Status::kOk;
    }

    m5auth::vault_runtime::Status set_last_used(
        const std::optional<m5auth::vault_runtime::CredentialId>& credential_id
    ) override {
        snapshot.last_used = credential_id;
        return m5auth::vault_runtime::Status::kOk;
    }

    m5auth::vault_runtime::Status erase_all() override {
        ++erase_calls;
        if (erase_result != m5auth::vault_runtime::Status::kOk) return erase_result;
        snapshot = {};
        return m5auth::vault_runtime::Status::kOk;
    }

    m5auth::vault_runtime::PersistedSnapshot snapshot{};
    m5auth::vault_runtime::Status erase_result{m5auth::vault_runtime::Status::kOk};
    int erase_calls{0};
};

class TestPresence final : public m5auth::session::protocol_v2::PresenceBinding {
public:
    bool begin_presence(
        m5auth::session::PresenceOperation operation,
        const m5auth::session::AttemptId& attempt_id,
        std::uint64_t now_ms
    ) override {
        return gate_.begin(operation, attempt_id, now_ms, generation_);
    }

    bool consume_presence(
        const m5auth::session::AttemptId& attempt_id,
        std::uint64_t now_ms
    ) override {
        return gate_.consume_confirmation(attempt_id, now_ms);
    }

    void cancel_presence() override {
        gate_.cancel();
    }

    bool presence_confirmed() const override {
        return gate_.state() == m5auth::session::PresenceState::kConfirmed;
    }

    bool confirm_fresh(std::uint64_t now_ms) {
        gate_.observe_input_state(false);
        gate_.observe_input_state(false);
        gate_.observe_input_state(true);
        ++generation_;
        return gate_.confirm_current(now_ms, generation_);
    }

    bool try_preheld(std::uint64_t now_ms) {
        gate_.observe_input_state(true);
        gate_.observe_input_state(true);
        ++generation_;
        return gate_.confirm_current(now_ms, generation_);
    }

private:
    m5auth::session::UserPresenceGate gate_{};
    std::uint64_t generation_{0};
};

class FakeBindingSource final : public m5auth::provisioning::SessionV2BindingSource {
public:
    bool snapshot(m5auth::provisioning::SessionV2DeviceSnapshot* output) const override {
        if (output == nullptr) return false;
        *output = {};
        output->device_id = "behavior-test";
        return true;
    }
};

class FakeSessionVmkSink final : public m5auth::provisioning::SessionV2VmkSink {
public:
    bool install_vmk(
        const m5auth::session::protocol_v2::BeginContext&,
        const m5auth::session::Vmk&
    ) override {
        return true;
    }
};

m5auth::vault::VaultEnvelope make_envelope(
    const m5auth::vault_runtime::Vmk& vmk,
    const std::array<std::uint8_t, m5auth::vault::kVaultIdBytes>& vault_id
) {
    m5auth::vault::VaultPlaintext plaintext;
    m5auth::vault::CredentialRecord credential;
    credential.credential_id = sequence<m5auth::vault::kCredentialIdBytes>(0x40);
    credential.secret = {
        0x53, 0x59, 0x4e, 0x54, 0x48, 0x45, 0x54, 0x49,
        0x43, 0x2d, 0x53, 0x45, 0x43, 0x52, 0x45, 0x54,
    };
    credential.issuer = "Synthetic";
    credential.account = "factory-reset-test";
    credential.display_name = "Factory Reset Test";
    plaintext.credentials.push_back(std::move(credential));

    std::vector<std::uint8_t> encoded;
    assert(m5auth::vault::encode_plaintext(
        plaintext,
        encoded,
        m5auth::vault::kVaultFormatVersion1
    ));
    m5auth::vault_runtime::wipe_plaintext(&plaintext);

    m5auth::vault::VaultEnvelope envelope;
    const auto nonce = sequence<m5auth::vault::kVaultNonceBytes>(0x70);
    assert(m5auth::vault::encrypt_vault_with_nonce(
        encoded,
        vmk,
        vault_id,
        1,
        nonce,
        envelope,
        m5auth::vault::kVaultFormatVersion1
    ));
    m5auth::vault_runtime::secure_zero(encoded.data(), encoded.size());
    return envelope;
}

std::string request(int id, std::string_view op, std::string_view params = "{}") {
    return "{\"v\":2,\"id\":" + std::to_string(id) +
        ",\"op\":\"" + std::string(op) + "\",\"params\":" + std::string(params) + "}";
}

struct ParsedResponse {
    bool ok{false};
    std::string error;
    std::string attempt_id;
    std::string state;
    bool reset_capability{false};
};

ParsedResponse parse_response(const std::string& response) {
    ParsedResponse parsed;
    cJSON* root = cJSON_ParseWithLength(response.data(), response.size());
    assert(root != nullptr);
    parsed.ok = cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(root, "ok"));
    cJSON* error = cJSON_GetObjectItemCaseSensitive(root, "error");
    if (cJSON_IsObject(error)) {
        cJSON* code = cJSON_GetObjectItemCaseSensitive(error, "code");
        if (cJSON_IsString(code) && code->valuestring != nullptr) parsed.error = code->valuestring;
    }
    cJSON* data = cJSON_GetObjectItemCaseSensitive(root, "data");
    if (cJSON_IsObject(data)) {
        cJSON* attempt = cJSON_GetObjectItemCaseSensitive(data, "attempt_id");
        if (cJSON_IsString(attempt) && attempt->valuestring != nullptr) parsed.attempt_id = attempt->valuestring;
        cJSON* state = cJSON_GetObjectItemCaseSensitive(data, "state");
        if (cJSON_IsString(state) && state->valuestring != nullptr) parsed.state = state->valuestring;
        parsed.reset_capability = cJSON_IsTrue(
            cJSON_GetObjectItemCaseSensitive(data, m5auth::provisioning::kFactoryResetPresenceCapability)
        );
    }
    cJSON_Delete(root);
    return parsed;
}

std::string attempt_params(const std::string& attempt_id) {
    return "{\"attempt_id\":\"" + attempt_id + "\"}";
}

class Fixture {
public:
    Fixture()
        : runtime(persistence),
          time_service(runtime, clock, runtime_mutex),
          coordinator(presence),
          session_handler(coordinator, binding_source, session_vmk_sink),
          vmk_sink(runtime, registration, runtime_mutex),
          metadata(m5auth::core::metadata_for("host-test", "behavior-test")),
          handler(
              metadata,
              runtime,
              registration,
              time_service,
              session_handler,
              vmk_sink,
              presence,
              runtime_mutex,
              [&]() { ++security_boundary_calls; }
          ) {
        g_registration_model = &registration_model;
        g_random_seed = 1;
        assert(runtime.initialize() == m5auth::vault_runtime::Status::kUnprovisioned);
        assert(runtime.format_for_schema2() == m5auth::vault_runtime::Status::kOk);

        vmk = sequence<m5auth::vault::kVmkBytes>(0x10);
        vault_id = sequence<m5auth::vault::kVaultIdBytes>(0x20);
        auto envelope = make_envelope(vmk, vault_id);
        assert(runtime.install_encrypted_vault(std::move(envelope), vmk) ==
            m5auth::vault_runtime::Status::kOk);
        assert(runtime.unlock(vmk, 100) == m5auth::vault_runtime::Status::kOk);

        registration_model.snapshot.device_id = sequence<m5auth::registration::kDeviceIdBytes>(0x30);
        registration_model.snapshot.registration_present = true;
        registration_model.snapshot.vault_id = vault_id;
        registration_model.snapshot.registration_id =
            sequence<m5auth::registration::kRegistrationIdBytes>(0x50);
        registration_model.snapshot.epoch = 1;
    }

    ~Fixture() {
        g_registration_model = nullptr;
    }

    void assert_healthy_unerased() {
        m5auth::vault_runtime::Metadata runtime_metadata{};
        assert(runtime.metadata(&runtime_metadata) == m5auth::vault_runtime::Status::kOk);
        assert(runtime_metadata.state == m5auth::vault_runtime::State::kUnlocked);
        assert(runtime_metadata.has_vault);
        assert(persistence.snapshot.has_vault);
        assert(registration_model.snapshot.registration_present);
    }

    FakePersistence persistence;
    m5auth::vault_runtime::Runtime runtime;
    std::recursive_mutex runtime_mutex;
    m5auth::registration::Store registration;
    m5auth::time::TrustedClock clock;
    m5auth::time::TimeService time_service;
    TestPresence presence;
    m5auth::session::protocol_v2::AttemptCoordinator coordinator;
    FakeBindingSource binding_source;
    FakeSessionVmkSink session_vmk_sink;
    m5auth::provisioning::StagedSessionV2Handler session_handler;
    m5auth::provisioning::CanonicalVmkSink vmk_sink;
    m5auth::core::DeviceMetadata metadata;
    int security_boundary_calls{0};
    m5auth::provisioning::CanonicalProtocolV2Handler handler;
    RegistrationModel registration_model;
    m5auth::vault_runtime::Vmk vmk{};
    std::array<std::uint8_t, m5auth::vault::kVaultIdBytes> vault_id{};
};

void legacy_raw_reset_is_non_destructive() {
    Fixture fixture;
    const ParsedResponse hello = parse_response(fixture.handler.handle_line(request(1, "hello"), 1'000));
    assert(hello.ok);
    assert(hello.reset_capability);

    const ParsedResponse response = parse_response(
        fixture.handler.handle_line(request(2, "factory_reset"), 1'001)
    );
    assert(!response.ok);
    assert(response.error == "presence_required");
    assert(fixture.persistence.erase_calls == 0);
    assert(fixture.registration_model.clear_calls == 0);
    fixture.assert_healthy_unerased();
}

void no_presence_stale_cancel_timeout_and_supersession_do_not_erase() {
    Fixture fixture;

    ParsedResponse begin = parse_response(
        fixture.handler.handle_line(request(10, m5auth::provisioning::kFactoryResetBeginOperation), 10'000)
    );
    assert(begin.ok && !begin.attempt_id.empty());
    ParsedResponse status = parse_response(fixture.handler.handle_line(
        request(11, m5auth::provisioning::kFactoryResetStatusOperation, attempt_params(begin.attempt_id)),
        10'001
    ));
    assert(status.ok && status.state == "awaiting_confirmation");

    ParsedResponse commit = parse_response(fixture.handler.handle_line(
        request(12, m5auth::provisioning::kFactoryResetCommitOperation, attempt_params(begin.attempt_id)),
        10'002
    ));
    assert(!commit.ok && commit.error == "presence_required");
    fixture.assert_healthy_unerased();

    assert(!fixture.presence.try_preheld(10'003));
    commit = parse_response(fixture.handler.handle_line(
        request(13, m5auth::provisioning::kFactoryResetCommitOperation, attempt_params(begin.attempt_id)),
        10'004
    ));
    assert(!commit.ok && commit.error == "presence_required");
    fixture.assert_healthy_unerased();

    ParsedResponse cancelled = parse_response(fixture.handler.handle_line(
        request(14, m5auth::provisioning::kFactoryResetCancelOperation, attempt_params(begin.attempt_id)),
        10'005
    ));
    assert(cancelled.ok);
    commit = parse_response(fixture.handler.handle_line(
        request(15, m5auth::provisioning::kFactoryResetCommitOperation, attempt_params(begin.attempt_id)),
        10'006
    ));
    assert(!commit.ok && commit.error == "invalid_state");

    begin = parse_response(
        fixture.handler.handle_line(request(16, m5auth::provisioning::kFactoryResetBeginOperation), 20'000)
    );
    assert(begin.ok);
    status = parse_response(fixture.handler.handle_line(
        request(17, m5auth::provisioning::kFactoryResetStatusOperation, attempt_params(begin.attempt_id)),
        20'000 + m5auth::session::kAttemptTtlMs
    ));
    assert(!status.ok && status.error == "expired");
    status = parse_response(fixture.handler.handle_line(
        request(18, m5auth::provisioning::kFactoryResetStatusOperation, attempt_params(begin.attempt_id)),
        20'000 + m5auth::session::kAttemptTtlMs + 1
    ));
    assert(!status.ok && status.error == "invalid_state");

    const ParsedResponse first = parse_response(
        fixture.handler.handle_line(request(19, m5auth::provisioning::kFactoryResetBeginOperation), 60'000)
    );
    const ParsedResponse second = parse_response(
        fixture.handler.handle_line(request(20, m5auth::provisioning::kFactoryResetBeginOperation), 60'010)
    );
    assert(first.ok && second.ok && first.attempt_id != second.attempt_id);
    status = parse_response(fixture.handler.handle_line(
        request(21, m5auth::provisioning::kFactoryResetStatusOperation, attempt_params(first.attempt_id)),
        60'011
    ));
    assert(!status.ok && status.error == "invalid_state");
    fixture.handler.handle_line(
        request(22, m5auth::provisioning::kFactoryResetCancelOperation, attempt_params(second.attempt_id)),
        60'012
    );

    assert(fixture.persistence.erase_calls == 0);
    fixture.assert_healthy_unerased();
}

void disconnect_invalidates_before_and_after_confirmation() {
    Fixture fixture;

    ParsedResponse begin = parse_response(
        fixture.handler.handle_line(request(30, m5auth::provisioning::kFactoryResetBeginOperation), 70'000)
    );
    assert(begin.ok);
    fixture.handler.disconnect();
    ParsedResponse replay = parse_response(fixture.handler.handle_line(
        request(31, m5auth::provisioning::kFactoryResetStatusOperation, attempt_params(begin.attempt_id)),
        70'001
    ));
    assert(!replay.ok && replay.error == "invalid_state");

    begin = parse_response(
        fixture.handler.handle_line(request(32, m5auth::provisioning::kFactoryResetBeginOperation), 71'000)
    );
    assert(begin.ok);
    assert(fixture.presence.confirm_fresh(71'001));
    ParsedResponse status = parse_response(fixture.handler.handle_line(
        request(33, m5auth::provisioning::kFactoryResetStatusOperation, attempt_params(begin.attempt_id)),
        71'002
    ));
    assert(status.ok && status.state == "confirmed");
    fixture.handler.disconnect();
    replay = parse_response(fixture.handler.handle_line(
        request(34, m5auth::provisioning::kFactoryResetCommitOperation, attempt_params(begin.attempt_id)),
        71'003
    ));
    assert(!replay.ok && replay.error == "invalid_state");
    assert(fixture.persistence.erase_calls == 0);
    fixture.assert_healthy_unerased();
}

void successful_commit_is_one_shot_and_erases_runtime_and_registration() {
    Fixture fixture;
    const ParsedResponse begin = parse_response(
        fixture.handler.handle_line(request(40, m5auth::provisioning::kFactoryResetBeginOperation), 80'000)
    );
    assert(begin.ok);
    assert(fixture.presence.confirm_fresh(80'001));

    ParsedResponse commit = parse_response(fixture.handler.handle_line(
        request(41, m5auth::provisioning::kFactoryResetCommitOperation, attempt_params(begin.attempt_id)),
        80'002
    ));
    assert(commit.ok);
    assert(fixture.persistence.erase_calls == 1);
    assert(fixture.registration_model.clear_calls == 1);
    assert(!fixture.persistence.snapshot.has_vault);
    assert(!fixture.registration_model.snapshot.registration_present);

    m5auth::vault_runtime::Metadata metadata{};
    assert(fixture.runtime.metadata(&metadata) == m5auth::vault_runtime::Status::kOk);
    assert(metadata.state == m5auth::vault_runtime::State::kUnprovisioned);
    assert(!metadata.has_vault);

    commit = parse_response(fixture.handler.handle_line(
        request(42, m5auth::provisioning::kFactoryResetCommitOperation, attempt_params(begin.attempt_id)),
        80'003
    ));
    assert(!commit.ok && commit.error == "invalid_state");
    assert(fixture.persistence.erase_calls == 1);
}

void terminal_erase_failure_consumes_authorization() {
    Fixture fixture;
    fixture.persistence.erase_result = m5auth::vault_runtime::Status::kIo;
    const ParsedResponse begin = parse_response(
        fixture.handler.handle_line(request(50, m5auth::provisioning::kFactoryResetBeginOperation), 90'000)
    );
    assert(begin.ok);
    assert(fixture.presence.confirm_fresh(90'001));

    ParsedResponse commit = parse_response(fixture.handler.handle_line(
        request(51, m5auth::provisioning::kFactoryResetCommitOperation, attempt_params(begin.attempt_id)),
        90'002
    ));
    assert(!commit.ok && commit.error == "reset_failed");
    assert(fixture.persistence.erase_calls == 1);
    assert(fixture.registration_model.clear_calls == 0);

    commit = parse_response(fixture.handler.handle_line(
        request(52, m5auth::provisioning::kFactoryResetCommitOperation, attempt_params(begin.attempt_id)),
        90'003
    ));
    assert(!commit.ok && commit.error == "invalid_state");
    assert(fixture.persistence.erase_calls == 1);
}

void locked_state_fails_closed() {
    Fixture fixture;
    assert(fixture.runtime.lock() == m5auth::vault_runtime::Status::kOk);
    ParsedResponse response = parse_response(
        fixture.handler.handle_line(request(60, m5auth::provisioning::kFactoryResetBeginOperation), 100'000)
    );
    assert(!response.ok && response.error == "invalid_state");
    response = parse_response(
        fixture.handler.handle_line(request(61, "factory_reset"), 100'001)
    );
    assert(!response.ok && response.error == "invalid_state");
    assert(fixture.persistence.erase_calls == 0);
}

void recovery_reset_remains_fresh_presence_gated() {
    Fixture fixture;
    fixture.registration_model.snapshot.registration_present = false;

    const ParsedResponse begin = parse_response(
        fixture.handler.handle_line(request(70, "factory_reset.recovery_begin"), 110'000)
    );
    assert(begin.ok && !begin.attempt_id.empty());
    ParsedResponse complete = parse_response(fixture.handler.handle_line(
        request(71, "factory_reset.recovery_complete", attempt_params(begin.attempt_id)),
        110'001
    ));
    assert(!complete.ok && complete.error == "presence_required");
    assert(fixture.persistence.erase_calls == 0);

    assert(fixture.presence.confirm_fresh(110'002));
    ParsedResponse status = parse_response(fixture.handler.handle_line(
        request(72, "factory_reset.recovery_status", attempt_params(begin.attempt_id)),
        110'003
    ));
    assert(status.ok && status.state == "confirmed");
    complete = parse_response(fixture.handler.handle_line(
        request(73, "factory_reset.recovery_complete", attempt_params(begin.attempt_id)),
        110'004
    ));
    assert(complete.ok);
    assert(fixture.persistence.erase_calls == 1);
}

}  // namespace

extern "C" void esp_fill_random(void* buffer, std::size_t length) {
    auto* bytes = static_cast<std::uint8_t*>(buffer);
    for (std::size_t index = 0; index < length; ++index) {
        bytes[index] = g_random_seed++;
        if (g_random_seed == 0) g_random_seed = 1;
    }
}

namespace m5auth::registration {

Status Store::snapshot(Snapshot* output) const {
    if (output == nullptr || g_registration_model == nullptr) return Status::kIo;
    *output = g_registration_model->snapshot;
    return g_registration_model->snapshot_status;
}

Status Store::clear_registration() {
    if (g_registration_model == nullptr) return Status::kIo;
    ++g_registration_model->clear_calls;
    if (g_registration_model->clear_result != Status::kOk) return g_registration_model->clear_result;
    g_registration_model->snapshot.registration_present = false;
    g_registration_model->snapshot.vault_id.fill(0);
    g_registration_model->snapshot.registration_id.fill(0);
    g_registration_model->snapshot.epoch = 0;
    g_registration_model->snapshot.brk_public_key.fill(0);
    return Status::kOk;
}

Status Store::clear_corrupt_registration_for_recovery() {
    return clear_registration();
}

std::string device_id_text(const DeviceId& device_id) {
    static constexpr char hex[] = "0123456789abcdef";
    std::string result;
    result.reserve(device_id.size() * 2);
    for (const std::uint8_t byte : device_id) {
        result.push_back(hex[(byte >> 4) & 0x0f]);
        result.push_back(hex[byte & 0x0f]);
    }
    return result;
}

}  // namespace m5auth::registration

namespace m5auth::time {

TimeService::TimeService(vault_runtime::Runtime& runtime, TrustedClock& clock)
    : vault_runtime_(runtime), clock_(clock) {}

TimeService::TimeService(
    vault_runtime::Runtime& runtime,
    TrustedClock& clock,
    std::recursive_mutex& runtime_access_mutex
) : vault_runtime_(runtime),
    runtime_access_mutex_(&runtime_access_mutex),
    clock_(clock) {}

TimeService::~TimeService() = default;

Snapshot TimeService::status() const {
    return {};
}

SyncResult TimeService::sync_from_usb(std::uint64_t) {
    return SyncResult::kOk;
}

void TimeService::teardown_network() {}

const char* sync_result_code(SyncResult result) {
    return result == SyncResult::kOk ? "ok" : "sync_failed";
}

const char* readiness_name(Readiness readiness) {
    switch (readiness) {
        case Readiness::kNotSynced: return "not_synced";
        case Readiness::kReady: return "ready";
        case Readiness::kStale: return "stale";
    }
    return "not_synced";
}

const char* source_name(Source source) {
    switch (source) {
        case Source::kNone: return "none";
        case Source::kNtp: return "ntp";
        case Source::kUsb: return "usb";
    }
    return "none";
}

}  // namespace m5auth::time

namespace m5auth::session {

struct DeviceSession::Impl {};

DeviceSession::DeviceSession() : impl_(std::make_unique<Impl>()) {}
DeviceSession::~DeviceSession() = default;

}  // namespace m5auth::session

namespace m5auth::session::protocol_v2 {

AttemptCoordinator::AttemptCoordinator(PresenceBinding& presence)
    : presence_(presence) {}

AttemptCoordinator::~AttemptCoordinator() {
    cancel();
}

bool AttemptCoordinator::expire(std::uint64_t) {
    return false;
}

void AttemptCoordinator::cancel() {
    presence_.cancel_presence();
    active_ = false;
    state_ = AttemptState::kIdle;
}

}  // namespace m5auth::session::protocol_v2

namespace m5auth::provisioning {

StagedSessionV2Handler::StagedSessionV2Handler(
    session::protocol_v2::AttemptCoordinator& coordinator,
    const SessionV2BindingSource& binding_source,
    SessionV2VmkSink& vmk_sink
) : coordinator_(coordinator), binding_source_(binding_source), vmk_sink_(vmk_sink) {}

StagedSessionV2Handler::~StagedSessionV2Handler() {
    disconnect();
}

std::string StagedSessionV2Handler::handle_line(std::string_view, std::uint64_t) {
    return R"({"v":2,"id":0,"ok":false,"error":{"code":"unsupported_op"}})";
}

void StagedSessionV2Handler::clear_context() {
    context_ = {};
    context_active_ = false;
}

void StagedSessionV2Handler::disconnect() {
    coordinator_.disconnect();
    clear_context();
}

CanonicalVmkSink::CanonicalVmkSink(
    vault_runtime::Runtime& runtime,
    registration::Store& registration,
    std::recursive_mutex& runtime_access_mutex
) : runtime_(runtime),
    registration_(registration),
    runtime_access_mutex_(runtime_access_mutex) {}

CanonicalVmkSink::~CanonicalVmkSink() {
    cancel_pending();
}

bool CanonicalVmkSink::prepare_attempt(const session::protocol_v2::BeginContext&) {
    cancel_pending();
    return true;
}

bool CanonicalVmkSink::install_vmk(
    const session::protocol_v2::BeginContext& context,
    const session::Vmk& vmk
) {
    pending_context_ = context;
    pending_vmk_ = vmk;
    pending_ = true;
    return true;
}

void CanonicalVmkSink::arm_pending_deadline(std::uint64_t now_ms) {
    deadline_armed_ = true;
    pending_expires_at_ms_ = now_ms + kPendingVaultVmkTtlMs;
}

bool CanonicalVmkSink::expire_pending(std::uint64_t now_ms) {
    if (!pending_ || !deadline_armed_ || now_ms < pending_expires_at_ms_) return false;
    cancel_pending();
    return true;
}

void CanonicalVmkSink::cancel_pending() {
    pending_vmk_.fill(0);
    pending_context_ = {};
    pending_ = false;
    deadline_armed_ = false;
    pending_expires_at_ms_ = 0;
}

bool CanonicalVmkSink::install_initial_vault(vault::VaultEnvelope, std::uint64_t) { return false; }
bool CanonicalVmkSink::install_recovered_vault(vault::VaultEnvelope, std::uint64_t) { return false; }
bool CanonicalVmkSink::install_rekeyed_vault(
    std::uint64_t,
    vault::VaultEnvelope,
    std::uint64_t
) { return false; }

bool CanonicalVmkSink::has_pending_vmk() const { return pending_; }
session::protocol_v2::Operation CanonicalVmkSink::pending_operation() const {
    return pending_context_.operation;
}

}  // namespace m5auth::provisioning

int main() {
    legacy_raw_reset_is_non_destructive();
    no_presence_stale_cancel_timeout_and_supersession_do_not_erase();
    disconnect_invalidates_before_and_after_confirmation();
    successful_commit_is_one_shot_and_erases_runtime_and_registration();
    terminal_erase_failure_consumes_authorization();
    locked_state_fails_closed();
    recovery_reset_remains_fresh_presence_gated();
    return 0;
}
