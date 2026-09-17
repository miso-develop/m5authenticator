#include <array>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "cJSON.h"
#include "m5auth/core/metadata.hpp"
#include "m5auth/provisioning/canonical_protocol_v2.hpp"
#include "m5auth/session/protocol_v2.hpp"
#include "m5auth/session/session.hpp"
#include "m5auth/time/time_service.hpp"
#include "m5auth/vault.hpp"
#include "m5auth/vault_runtime/runtime.hpp"

namespace {

using m5auth::session::AttemptId;
using m5auth::vault_runtime::CredentialId;
using m5auth::vault_runtime::Metadata;
using m5auth::vault_runtime::PersistedSnapshot;
using m5auth::vault_runtime::Persistence;
using m5auth::vault_runtime::Runtime;
using m5auth::vault_runtime::State;
using m5auth::vault_runtime::Status;
using m5auth::vault_runtime::Vmk;

m5auth::registration::Snapshot g_registration_snapshot{};
m5auth::registration::Status g_registration_status{m5auth::registration::Status::kOk};
m5auth::registration::Status g_registration_clear_status{m5auth::registration::Status::kOk};
int g_registration_clear_calls = 0;

std::uint8_t g_random_seed = 1;

extern "C" void esp_fill_random(void* buffer, std::size_t length) {
    auto* output = static_cast<std::uint8_t*>(buffer);
    const std::uint8_t seed = g_random_seed++;
    for (std::size_t index = 0; index < length; ++index) {
        output[index] = static_cast<std::uint8_t>(seed + index + 1);
    }
}

template <std::size_t N>
std::array<std::uint8_t, N> sequence(std::uint8_t start) {
    std::array<std::uint8_t, N> result{};
    for (std::size_t index = 0; index < result.size(); ++index) {
        result[index] = static_cast<std::uint8_t>(start + index);
    }
    return result;
}

class FakePersistence final : public Persistence {
public:
    Status load(PersistedSnapshot* output) override {
        if (output == nullptr) return Status::kInvalidArgument;
        *output = snapshot;
        return snapshot.schema_ready ? Status::kOk : Status::kUnprovisioned;
    }

    Status format_schema2() override {
        snapshot = PersistedSnapshot{};
        snapshot.schema_ready = true;
        return Status::kOk;
    }

    Status replace_envelope(
        std::uint64_t expected_generation,
        const m5auth::vault::VaultEnvelope& envelope
    ) override {
        if (!snapshot.schema_ready) return Status::kNotReady;
        if (expected_generation == 0) {
            if (snapshot.has_vault) return Status::kGenerationMismatch;
        } else if (!snapshot.has_vault ||
                   snapshot.envelope.generation != expected_generation ||
                   envelope.generation != expected_generation + 1 ||
                   envelope.vault_id != snapshot.envelope.vault_id) {
            return Status::kGenerationMismatch;
        }
        snapshot.has_vault = true;
        snapshot.envelope = envelope;
        return Status::kOk;
    }

    Status set_last_used(const std::optional<CredentialId>& credential_id) override {
        snapshot.last_used = credential_id;
        return Status::kOk;
    }

    Status erase_all() override {
        ++erase_calls;
        if (erase_result != Status::kOk) return erase_result;
        snapshot = PersistedSnapshot{};
        return Status::kOk;
    }

    PersistedSnapshot snapshot{};
    Status erase_result{Status::kOk};
    int erase_calls{0};
};

m5auth::vault::VaultEnvelope make_envelope(
    const Vmk& vmk,
    const std::array<std::uint8_t, m5auth::vault::kVaultIdBytes>& vault_id
) {
    m5auth::vault::VaultPlaintext plaintext;
    m5auth::vault::CredentialRecord credential;
    credential.credential_id = sequence<m5auth::vault::kCredentialIdBytes>(0x40);
    credential.secret = {0x53, 0x59, 0x4e, 0x54, 0x48, 0x45, 0x54, 0x49, 0x43};
    credential.issuer = "Synthetic Issuer";
    credential.account = "synthetic-account";
    credential.display_name = "Synthetic Display";
    credential.algorithm = m5auth::vault::TotpAlgorithm::kSha1;
    credential.digits = 6;
    credential.period_seconds = 30;
    plaintext.credentials.push_back(std::move(credential));

    std::vector<std::uint8_t> encoded;
    assert(m5auth::vault::encode_plaintext(
        plaintext,
        encoded,
        m5auth::vault::kCurrentVaultFormatVersion
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
        m5auth::vault::kCurrentVaultFormatVersion
    ));
    m5auth::vault_runtime::secure_zero(encoded.data(), encoded.size());
    return envelope;
}

class GatePresence final : public m5auth::session::protocol_v2::PresenceBinding {
public:
    bool begin_presence(
        m5auth::session::PresenceOperation operation,
        const AttemptId& attempt_id,
        std::uint64_t now_ms
    ) override {
        return gate.begin(operation, attempt_id, now_ms, input_generation);
    }

    bool consume_presence(const AttemptId& attempt_id, std::uint64_t now_ms) override {
        return gate.consume_confirmation(attempt_id, now_ms);
    }

    void cancel_presence() override {
        gate.cancel();
    }

    bool presence_confirmed() const override {
        return gate.state() == m5auth::session::PresenceState::kConfirmed;
    }

    void assert_preheld_does_not_confirm(std::uint64_t now_ms) {
        gate.observe_input_state(true);
        gate.observe_input_state(true);
        ++input_generation;
        assert(!gate.confirm_current(now_ms, input_generation));
        assert(gate.state() == m5auth::session::PresenceState::kAwaiting);
    }

    void assert_stale_edge_does_not_confirm(std::uint64_t now_ms) {
        gate.observe_input_state(false);
        gate.observe_input_state(false);
        assert(gate.input_armed());
        gate.observe_input_state(true);
        assert(!gate.confirm_current(now_ms, input_generation));
        assert(!gate.confirm_current(now_ms + 1, input_generation + 1));
        assert(gate.state() == m5auth::session::PresenceState::kAwaiting);
    }

    void confirm_fresh(std::uint64_t now_ms) {
        gate.observe_input_state(false);
        gate.observe_input_state(false);
        assert(gate.input_armed());
        gate.observe_input_state(true);
        ++input_generation;
        assert(gate.confirm_current(now_ms, input_generation));
        assert(gate.state() == m5auth::session::PresenceState::kConfirmed);
    }

    m5auth::session::UserPresenceGate gate;
    std::uint64_t input_generation{100};
};

class DummyBindingSource final : public m5auth::provisioning::SessionV2BindingSource {
public:
    bool snapshot(m5auth::provisioning::SessionV2DeviceSnapshot*) const override {
        return false;
    }
};

class DummySessionVmkSink final : public m5auth::provisioning::SessionV2VmkSink {
public:
    bool install_vmk(
        const m5auth::session::protocol_v2::BeginContext&,
        const m5auth::session::Vmk&
    ) override {
        return false;
    }
};

bool response_ok(const std::string& response) {
    cJSON* root = cJSON_ParseWithLength(response.data(), response.size());
    assert(root != nullptr);
    const bool ok = cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(root, "ok"));
    cJSON_Delete(root);
    return ok;
}

std::string response_error(const std::string& response) {
    cJSON* root = cJSON_ParseWithLength(response.data(), response.size());
    assert(root != nullptr);
    cJSON* error = cJSON_GetObjectItemCaseSensitive(root, "error");
    cJSON* code = error == nullptr ? nullptr : cJSON_GetObjectItemCaseSensitive(error, "code");
    assert(cJSON_IsString(code) && code->valuestring != nullptr);
    const std::string result(code->valuestring);
    cJSON_Delete(root);
    return result;
}

std::string response_data_string(const std::string& response, const char* key) {
    cJSON* root = cJSON_ParseWithLength(response.data(), response.size());
    assert(root != nullptr);
    cJSON* data = cJSON_GetObjectItemCaseSensitive(root, "data");
    cJSON* value = data == nullptr ? nullptr : cJSON_GetObjectItemCaseSensitive(data, key);
    assert(cJSON_IsString(value) && value->valuestring != nullptr);
    const std::string result(value->valuestring);
    cJSON_Delete(root);
    return result;
}

bool response_data_bool(const std::string& response, const char* key) {
    cJSON* root = cJSON_ParseWithLength(response.data(), response.size());
    assert(root != nullptr);
    cJSON* data = cJSON_GetObjectItemCaseSensitive(root, "data");
    cJSON* value = data == nullptr ? nullptr : cJSON_GetObjectItemCaseSensitive(data, key);
    assert(cJSON_IsBool(value));
    const bool result = cJSON_IsTrue(value);
    cJSON_Delete(root);
    return result;
}

std::string request(int id, std::string_view operation, std::string_view params = "{}") {
    return std::string("{\"v\":2,\"id\":") + std::to_string(id) +
        ",\"op\":\"" + std::string(operation) + "\",\"params\":" +
        std::string(params) + "}";
}

std::string attempt_params(const std::string& attempt_id) {
    return std::string("{\"attempt_id\":\"") + attempt_id + "\"}";
}

struct Fixture {
    FakePersistence persistence;
    Runtime runtime{persistence};
    std::recursive_mutex runtime_mutex;
    m5auth::time::TrustedClock clock;
    m5auth::time::TimeService time_service{runtime, clock, runtime_mutex};
    GatePresence presence;
    m5auth::session::protocol_v2::AttemptCoordinator coordinator{presence};
    DummyBindingSource binding_source;
    DummySessionVmkSink staged_vmk_sink;
    m5auth::provisioning::StagedSessionV2Handler session_handler{
        coordinator, binding_source, staged_vmk_sink
    };
    m5auth::registration::Store registration;
    m5auth::provisioning::CanonicalVmkSink canonical_vmk_sink{
        runtime, registration, runtime_mutex
    };
    m5auth::core::DeviceMetadata metadata{
        m5auth::core::metadata_for("M5StickS3", "host-test")
    };
    int security_boundary_clears{0};
    std::unique_ptr<m5auth::provisioning::CanonicalProtocolV2Handler> handler;
    Vmk vmk{sequence<m5auth::vault::kVmkBytes>(0x10)};
    std::array<std::uint8_t, m5auth::vault::kVaultIdBytes> vault_id{
        sequence<m5auth::vault::kVaultIdBytes>(0x20)
    };

    Fixture() {
        g_registration_snapshot = m5auth::registration::Snapshot{};
        g_registration_snapshot.device_id = sequence<m5auth::registration::kDeviceIdBytes>(0x01);
        g_registration_snapshot.registration_present = true;
        g_registration_snapshot.vault_id = vault_id;
        g_registration_snapshot.registration_id =
            sequence<m5auth::registration::kRegistrationIdBytes>(0x30);
        g_registration_status = m5auth::registration::Status::kOk;
        g_registration_clear_status = m5auth::registration::Status::kOk;
        g_registration_clear_calls = 0;

        assert(runtime.initialize() == Status::kUnprovisioned);
        assert(runtime.format_for_schema2() == Status::kOk);
        auto envelope = make_envelope(vmk, vault_id);
        assert(runtime.install_encrypted_vault(std::move(envelope), vmk) == Status::kOk);
        assert(runtime.unlock(vmk, 100) == Status::kOk);
        assert(runtime.unlocked());

        handler = std::make_unique<m5auth::provisioning::CanonicalProtocolV2Handler>(
            metadata,
            runtime,
            registration,
            time_service,
            session_handler,
            canonical_vmk_sink,
            presence,
            runtime_mutex,
            [this]() { ++security_boundary_clears; }
        );
    }

    std::string begin(int id, std::uint64_t now_ms) {
        const auto response = handler->handle_line(request(id, "factory_reset.begin"), now_ms);
        assert(response_ok(response));
        return response_data_string(response, "attempt_id");
    }

    void assert_unerased() {
        assert(persistence.erase_calls == 0);
        Metadata current{};
        assert(runtime.metadata(&current) == Status::kOk);
        assert(current.state != State::kUnprovisioned);
        assert(current.has_vault);
    }
};

void hello_advertises_capability_and_legacy_is_non_destructive() {
    Fixture fixture;
    const auto hello = fixture.handler->handle_line(request(1, "hello"), 1'000);
    assert(response_ok(hello));
    assert(response_data_bool(hello, m5auth::provisioning::kFactoryResetPresenceCapability));

    const auto legacy = fixture.handler->handle_line(request(2, "factory_reset"), 1'001);
    assert(!response_ok(legacy));
    assert(response_error(legacy) == "presence_required");
    fixture.assert_unerased();
}

void stale_preheld_and_stale_edge_cannot_authorize() {
    {
        Fixture fixture;
        const std::string attempt = fixture.begin(10, 10'000);
        fixture.presence.assert_preheld_does_not_confirm(10'001);
        const auto status = fixture.handler->handle_line(
            request(11, "factory_reset.status", attempt_params(attempt)), 10'002
        );
        assert(response_ok(status));
        assert(response_data_string(status, "state") == "awaiting_confirmation");
        const auto commit = fixture.handler->handle_line(
            request(12, "factory_reset.commit", attempt_params(attempt)), 10'003
        );
        assert(!response_ok(commit));
        assert(response_error(commit) == "presence_required");
        fixture.assert_unerased();
    }
    {
        Fixture fixture;
        const std::string attempt = fixture.begin(13, 11'000);
        fixture.presence.assert_stale_edge_does_not_confirm(11'001);
        const auto commit = fixture.handler->handle_line(
            request(14, "factory_reset.commit", attempt_params(attempt)), 11'003
        );
        assert(!response_ok(commit));
        assert(response_error(commit) == "presence_required");
        fixture.assert_unerased();
    }
}

void cancel_timeout_and_supersession_invalidate_attempts() {
    {
        Fixture fixture;
        const std::string attempt = fixture.begin(20, 20'000);
        const auto cancelled = fixture.handler->handle_line(
            request(21, "factory_reset.cancel", attempt_params(attempt)), 20'001
        );
        assert(response_ok(cancelled));
        const auto replay = fixture.handler->handle_line(
            request(22, "factory_reset.commit", attempt_params(attempt)), 20'002
        );
        assert(!response_ok(replay));
        assert(response_error(replay) == "invalid_state");
        fixture.assert_unerased();
    }
    {
        Fixture fixture;
        const std::string attempt = fixture.begin(23, 30'000);
        const auto expired = fixture.handler->handle_line(
            request(24, "factory_reset.status", attempt_params(attempt)), 60'000
        );
        assert(!response_ok(expired));
        assert(response_error(expired) == "expired");
        const auto replay = fixture.handler->handle_line(
            request(25, "factory_reset.commit", attempt_params(attempt)), 60'001
        );
        assert(!response_ok(replay));
        assert(response_error(replay) == "invalid_state");
        fixture.assert_unerased();
    }
    {
        Fixture fixture;
        const std::string first = fixture.begin(26, 70'000);
        const std::string second = fixture.begin(27, 70'100);
        assert(first != second);
        const auto stale = fixture.handler->handle_line(
            request(28, "factory_reset.status", attempt_params(first)), 70'101
        );
        assert(!response_ok(stale));
        assert(response_error(stale) == "invalid_state");
        fixture.presence.confirm_fresh(70'102);
        const auto cancelled = fixture.handler->handle_line(
            request(29, "factory_reset.cancel", attempt_params(second)), 70'103
        );
        assert(response_ok(cancelled));
        fixture.assert_unerased();
    }
}

void disconnect_invalidates_before_and_after_confirmation_and_replay() {
    {
        Fixture fixture;
        const std::string attempt = fixture.begin(30, 80'000);
        fixture.handler->disconnect();
        const auto stale = fixture.handler->handle_line(
            request(31, "factory_reset.status", attempt_params(attempt)), 80'001
        );
        assert(!response_ok(stale));
        assert(response_error(stale) == "invalid_state");
        const std::string replacement = fixture.begin(32, 80'010);
        assert(replacement != attempt);
        const auto replay = fixture.handler->handle_line(
            request(33, "factory_reset.commit", attempt_params(attempt)), 80'011
        );
        assert(!response_ok(replay));
        assert(response_error(replay) == "invalid_state");
        fixture.assert_unerased();
    }
    {
        Fixture fixture;
        const std::string attempt = fixture.begin(34, 90'000);
        fixture.presence.confirm_fresh(90'001);
        const auto confirmed = fixture.handler->handle_line(
            request(35, "factory_reset.status", attempt_params(attempt)), 90'002
        );
        assert(response_ok(confirmed));
        assert(response_data_string(confirmed, "state") == "confirmed");
        fixture.handler->disconnect();
        const auto replay = fixture.handler->handle_line(
            request(36, "factory_reset.commit", attempt_params(attempt)), 90'003
        );
        assert(!response_ok(replay));
        assert(response_error(replay) == "invalid_state");
        fixture.assert_unerased();
    }
}

void successful_commit_is_one_shot_and_erases_runtime() {
    Fixture fixture;
    const std::string attempt = fixture.begin(40, 100'000);
    fixture.presence.confirm_fresh(100'001);
    const auto committed = fixture.handler->handle_line(
        request(41, "factory_reset.commit", attempt_params(attempt)), 100'002
    );
    assert(response_ok(committed));
    assert(fixture.persistence.erase_calls == 1);
    assert(g_registration_clear_calls == 1);
    assert(fixture.security_boundary_clears == 1);

    Metadata metadata{};
    assert(fixture.runtime.metadata(&metadata) == Status::kOk);
    assert(metadata.state == State::kUnprovisioned);
    assert(!metadata.has_vault);
    assert(!fixture.runtime.unlocked());

    const auto replay = fixture.handler->handle_line(
        request(42, "factory_reset.commit", attempt_params(attempt)), 100'003
    );
    assert(!response_ok(replay));
    assert(response_error(replay) == "invalid_state");
    assert(fixture.persistence.erase_calls == 1);
}

void terminal_reset_failure_still_consumes_authorization() {
    Fixture fixture;
    fixture.persistence.erase_result = Status::kIo;
    const std::string attempt = fixture.begin(50, 110'000);
    fixture.presence.confirm_fresh(110'001);
    const auto failed = fixture.handler->handle_line(
        request(51, "factory_reset.commit", attempt_params(attempt)), 110'002
    );
    assert(!response_ok(failed));
    assert(response_error(failed) == "reset_failed");
    assert(fixture.persistence.erase_calls == 1);

    const auto replay = fixture.handler->handle_line(
        request(52, "factory_reset.commit", attempt_params(attempt)), 110'003
    );
    assert(!response_ok(replay));
    assert(response_error(replay) == "invalid_state");
    assert(fixture.persistence.erase_calls == 1);
}

void locked_normal_reset_is_unavailable() {
    Fixture fixture;
    assert(fixture.runtime.lock() == Status::kOk);
    const auto begin = fixture.handler->handle_line(request(60, "factory_reset.begin"), 120'000);
    assert(!response_ok(begin));
    assert(response_error(begin) == "invalid_state");
    const auto legacy = fixture.handler->handle_line(request(61, "factory_reset"), 120'001);
    assert(!response_ok(legacy));
    assert(response_error(legacy) == "invalid_state");
    fixture.assert_unerased();
}

void recovery_reset_flow_remains_separate_and_presence_gated() {
    Fixture fixture;
    g_registration_snapshot.registration_present = false;
    g_registration_snapshot.vault_id.fill(0);

    const auto healthy = fixture.handler->handle_line(request(70, "factory_reset.begin"), 130'000);
    assert(!response_ok(healthy));
    assert(response_error(healthy) == "invalid_state");
    fixture.assert_unerased();

    const auto recovery_begin = fixture.handler->handle_line(
        request(71, "factory_reset.recovery_begin"), 130'001
    );
    assert(response_ok(recovery_begin));
    const std::string attempt = response_data_string(recovery_begin, "attempt_id");

    const auto premature = fixture.handler->handle_line(
        request(72, "factory_reset.recovery_complete", attempt_params(attempt)), 130'002
    );
    assert(!response_ok(premature));
    assert(response_error(premature) == "presence_required");
    fixture.assert_unerased();

    fixture.presence.confirm_fresh(130'003);
    const auto committed = fixture.handler->handle_line(
        request(73, "factory_reset.recovery_complete", attempt_params(attempt)), 130'004
    );
    assert(response_ok(committed));
    assert(fixture.persistence.erase_calls == 1);
}

}  // namespace

namespace m5auth::registration {

Status Store::snapshot(Snapshot* output) const {
    if (output == nullptr) return Status::kInvalidArgument;
    if (g_registration_status == Status::kOk) *output = g_registration_snapshot;
    return g_registration_status;
}

Status Store::clear_registration() {
    ++g_registration_clear_calls;
    if (g_registration_clear_status != Status::kOk) return g_registration_clear_status;
    g_registration_snapshot.registration_present = false;
    g_registration_snapshot.vault_id.fill(0);
    g_registration_snapshot.registration_id.fill(0);
    g_registration_snapshot.epoch = 0;
    g_registration_snapshot.brk_public_key.fill(0);
    return Status::kOk;
}

Status Store::clear_corrupt_registration_for_recovery() {
    return clear_registration();
}

const char* status_code(Status status) {
    return status == Status::kOk ? "ok" : "registration_error";
}

std::string device_id_text(const DeviceId&) {
    return "0102030405060708090a0b0c0d0e0f10";
}

void secure_zero(void* data, std::size_t size) {
    volatile auto* cursor = static_cast<volatile std::uint8_t*>(data);
    while (size-- > 0) *cursor++ = 0;
}

}  // namespace m5auth::registration

namespace m5auth::session {

struct DeviceSession::Impl {};

DeviceSession::DeviceSession() : impl_(std::make_unique<Impl>()) {}
DeviceSession::~DeviceSession() = default;

}  // namespace m5auth::session

namespace m5auth::session::protocol_v2 {

AttemptCoordinator::AttemptCoordinator(PresenceBinding& presence)
    : presence_(presence) {}
AttemptCoordinator::~AttemptCoordinator() = default;

bool AttemptCoordinator::expire(std::uint64_t) {
    return false;
}

void AttemptCoordinator::cancel() {
    presence_.cancel_presence();
}

}  // namespace m5auth::session::protocol_v2

namespace m5auth::provisioning {

StagedSessionV2Handler::StagedSessionV2Handler(
    session::protocol_v2::AttemptCoordinator& coordinator,
    const SessionV2BindingSource& binding_source,
    SessionV2VmkSink& vmk_sink
) : coordinator_(coordinator), binding_source_(binding_source), vmk_sink_(vmk_sink) {}

StagedSessionV2Handler::~StagedSessionV2Handler() = default;

std::string StagedSessionV2Handler::handle_line(std::string_view, std::uint64_t) {
    return R"({"v":2,"id":0,"ok":false,"error":{"code":"unsupported_op"}})";
}

void StagedSessionV2Handler::disconnect() {}

std::string session_v2_message_too_large_response() {
    return R"({"v":2,"id":0,"ok":false,"error":{"code":"message_too_large"}})";
}

CanonicalVmkSink::CanonicalVmkSink(
    vault_runtime::Runtime& runtime,
    registration::Store& registration,
    std::recursive_mutex& runtime_access_mutex
) : runtime_(runtime), registration_(registration), runtime_access_mutex_(runtime_access_mutex) {}

CanonicalVmkSink::~CanonicalVmkSink() = default;

bool CanonicalVmkSink::prepare_attempt(const session::protocol_v2::BeginContext&) {
    return false;
}

bool CanonicalVmkSink::install_vmk(
    const session::protocol_v2::BeginContext&,
    const session::Vmk&
) {
    return false;
}

void CanonicalVmkSink::arm_pending_deadline(std::uint64_t) {}

bool CanonicalVmkSink::expire_pending(std::uint64_t) {
    return false;
}

void CanonicalVmkSink::cancel_pending() {}

bool CanonicalVmkSink::install_initial_vault(vault::VaultEnvelope, std::uint64_t) {
    return false;
}

bool CanonicalVmkSink::install_recovered_vault(vault::VaultEnvelope, std::uint64_t) {
    return false;
}

bool CanonicalVmkSink::install_rekeyed_vault(
    std::uint64_t,
    vault::VaultEnvelope,
    std::uint64_t
) {
    return false;
}

bool CanonicalVmkSink::has_pending_vmk() const {
    return false;
}

session::protocol_v2::Operation CanonicalVmkSink::pending_operation() const {
    return session::protocol_v2::Operation::kTrustedBrowserUnlock;
}

}  // namespace m5auth::provisioning

namespace m5auth::time {

const char* sync_result_code(SyncResult result) {
    return result == SyncResult::kOk ? "ok" : "time_error";
}

const char* readiness_name(Readiness readiness) {
    return readiness == Readiness::kReady ? "ready" :
        readiness == Readiness::kStale ? "stale" : "not_synced";
}

const char* source_name(Source source) {
    return source == Source::kUsb ? "usb" : source == Source::kNtp ? "ntp" : "none";
}

TimeService::TimeService(vault_runtime::Runtime& runtime, TrustedClock& clock)
    : vault_runtime_(runtime), clock_(clock) {}

TimeService::TimeService(
    vault_runtime::Runtime& runtime,
    TrustedClock& clock,
    std::recursive_mutex& runtime_access_mutex
) : vault_runtime_(runtime), runtime_access_mutex_(&runtime_access_mutex), clock_(clock) {}

TimeService::~TimeService() = default;

Snapshot TimeService::status() const {
    return Snapshot{};
}

SyncResult TimeService::sync_from_usb(std::uint64_t) {
    return SyncResult::kOk;
}

void TimeService::teardown_network() {}

}  // namespace m5auth::time

int main() {
    hello_advertises_capability_and_legacy_is_non_destructive();
    stale_preheld_and_stale_edge_cannot_authorize();
    cancel_timeout_and_supersession_invalidate_attempts();
    disconnect_invalidates_before_and_after_confirmation_and_replay();
    successful_commit_is_one_shot_and_erases_runtime();
    terminal_reset_failure_still_consumes_authorization();
    locked_normal_reset_is_unavailable();
    recovery_reset_flow_remains_separate_and_presence_gated();
    return 0;
}
