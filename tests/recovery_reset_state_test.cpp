#include <algorithm>
#include <cassert>
#include <fstream>
#include <iterator>
#include <string>
#include <string_view>

#include "m5auth/provisioning/factory_reset_authorization.hpp"
#include "m5auth/provisioning/recovery_reset.hpp"

int main() {
    using namespace m5auth;
    using provisioning::FactoryResetAuthorization;
    using provisioning::RecoveryResetDecision;

    vault_runtime::Metadata runtime{};
    registration::Snapshot registration{};

    // Normal unprovisioned ownership is not a recovery-reset condition.
    runtime.has_vault = false;
    registration.registration_present = false;
    assert(provisioning::classify_recovery_reset(
        runtime,
        registration::Status::kOk,
        registration,
        false
    ) == RecoveryResetDecision::kNotRequired);

    // Normal provisioned ownership with the same Vault identity is not eligible.
    runtime.has_vault = true;
    runtime.vault_id[0] = 0x11;
    registration.registration_present = true;
    registration.vault_id[0] = 0x11;
    assert(provisioning::classify_recovery_reset(
        runtime,
        registration::Status::kOk,
        registration,
        false
    ) == RecoveryResetDecision::kNotRequired);

    // Both partial-ownership directions require the explicit confirmed reset.
    registration.registration_present = false;
    assert(provisioning::classify_recovery_reset(
        runtime,
        registration::Status::kOk,
        registration,
        false
    ) == RecoveryResetDecision::kRequired);

    runtime.has_vault = false;
    registration.registration_present = true;
    assert(provisioning::classify_recovery_reset(
        runtime,
        registration::Status::kOk,
        registration,
        false
    ) == RecoveryResetDecision::kRequired);

    // A Vault/registration identity mismatch is also bounded recovery state.
    runtime.has_vault = true;
    runtime.vault_id.fill(0);
    runtime.vault_id[0] = 0x22;
    registration.registration_present = true;
    registration.vault_id.fill(0);
    registration.vault_id[0] = 0x33;
    assert(provisioning::classify_recovery_reset(
        runtime,
        registration::Status::kOk,
        registration,
        false
    ) == RecoveryResetDecision::kRequired);

    // Structural registration corruption is eligible only when Store proved
    // that the stable Device ID is valid and retained for explicit recovery.
    assert(provisioning::classify_recovery_reset(
        runtime,
        registration::Status::kCorrupt,
        registration,
        true
    ) == RecoveryResetDecision::kRequired);
    assert(provisioning::classify_recovery_reset(
        runtime,
        registration::Status::kCorrupt,
        registration,
        false
    ) == RecoveryResetDecision::kUnavailable);

    // Generic NVS I/O failures never authorize destructive cleanup.
    assert(provisioning::classify_recovery_reset(
        runtime,
        registration::Status::kIo,
        registration,
        true
    ) == RecoveryResetDecision::kUnavailable);

    // Healthy Factory Reset exposes an explicit capability and attempt-bound
    // operation vocabulary without changing Protocol v2 itself.
    assert(std::string_view(provisioning::kFactoryResetPresenceCapability) ==
        "factory_reset_presence_required");
    assert(std::string_view(provisioning::kFactoryResetBeginOperation) == "factory_reset.begin");
    assert(std::string_view(provisioning::kFactoryResetStatusOperation) == "factory_reset.status");
    assert(std::string_view(provisioning::kFactoryResetCancelOperation) == "factory_reset.cancel");
    assert(std::string_view(provisioning::kFactoryResetCommitOperation) == "factory_reset.commit");

    session::AttemptId attempt_a{};
    session::AttemptId attempt_b{};
    attempt_a[0] = 0xA1;
    attempt_b[0] = 0xB2;

    FactoryResetAuthorization authorization;
    assert(!authorization.active());
    assert(authorization.check(attempt_a, 1000) == FactoryResetAuthorization::Check::kInactive);

    authorization.begin(attempt_a, 1000);
    assert(authorization.active());
    assert(authorization.check(attempt_a, 1001) == FactoryResetAuthorization::Check::kOk);
    assert(authorization.check(attempt_b, 1001) == FactoryResetAuthorization::Check::kMismatch);
    assert(authorization.check(attempt_a, 1000 + session::kAttemptTtlMs) ==
        FactoryResetAuthorization::Check::kExpired);

    // A new begin supersedes the prior attempt identity.
    authorization.begin(attempt_b, 2000);
    assert(authorization.check(attempt_a, 2001) == FactoryResetAuthorization::Check::kMismatch);
    assert(authorization.check(attempt_b, 2001) == FactoryResetAuthorization::Check::kOk);

    // Terminal consumption makes replay impossible and zeroizes identity state.
    authorization.consume();
    assert(!authorization.active());
    assert(authorization.check(attempt_b, 2002) == FactoryResetAuthorization::Check::kInactive);
    assert(std::all_of(
        authorization.attempt_id().begin(),
        authorization.attempt_id().end(),
        [](std::uint8_t byte) { return byte == 0; }
    ));

    // Cancel/timeout clear the attempt identically and do not leave reusable state.
    authorization.begin(attempt_a, 3000);
    authorization.cancel();
    assert(authorization.check(attempt_a, 3001) == FactoryResetAuthorization::Check::kInactive);
    assert(std::all_of(
        authorization.attempt_id().begin(),
        authorization.attempt_id().end(),
        [](std::uint8_t byte) { return byte == 0; }
    ));
    authorization.begin(attempt_a, 4000);
    assert(authorization.expired(4000 + session::kAttemptTtlMs));
    authorization.cancel();
    assert(!authorization.active());

    // Pin the canonical Protocol integration as well as the standalone attempt
    // state. This protects the raw-USB and disconnect/replay security boundary
    // without introducing a second implementation of the production handler.
    std::ifstream protocol_file(
        "firmware/components/m5auth_provisioning/canonical_protocol_v2.cpp",
        std::ios::binary
    );
    assert(protocol_file.good());
    const std::string protocol_source(
        std::istreambuf_iterator<char>(protocol_file),
        std::istreambuf_iterator<char>()
    );
    const std::string_view protocol(protocol_source);

    const auto block_between = [&](std::string_view start_marker, std::string_view end_marker) {
        const std::size_t start = protocol.find(start_marker);
        assert(start != std::string_view::npos);
        const std::size_t end = protocol.find(end_marker, start + start_marker.size());
        assert(end != std::string_view::npos);
        return protocol.substr(start, end - start);
    };

    const auto hello_block = block_between(
        "if (operation == \"hello\")",
        "else if (operation == kFactoryResetBeginOperation)"
    );
    assert(hello_block.find("kFactoryResetPresenceCapability") != std::string_view::npos);

    const auto begin_block = block_between(
        "else if (operation == kFactoryResetBeginOperation)",
        "else if (operation == kFactoryResetStatusOperation)"
    );
    assert(begin_block.find("runtime_metadata.state != vault_runtime::State::kUnlocked") !=
        std::string_view::npos);
    assert(begin_block.find("esp_fill_random(attempt_id.data(), attempt_id.size())") !=
        std::string_view::npos);
    assert(begin_block.find("session::PresenceOperation::kFactoryReset") != std::string_view::npos);
    assert(begin_block.find("healthy_factory_reset_.begin(attempt_id, now_ms)") !=
        std::string_view::npos);

    const auto cancel_block = block_between(
        "else if (operation == kFactoryResetCancelOperation)",
        "else if (operation == kFactoryResetCommitOperation)"
    );
    assert(cancel_block.find("cancel_healthy_factory_reset();") != std::string_view::npos);

    const auto commit_block = block_between(
        "else if (operation == kFactoryResetCommitOperation)",
        "else if (operation == \"factory_reset.recovery_begin\")"
    );
    const std::size_t consume_presence = commit_block.find("reset_presence_.consume_presence(attempt_id, now_ms)");
    const std::size_t consume_authorization = commit_block.find("healthy_factory_reset_.consume();");
    const std::size_t erase_vault = commit_block.find("runtime_.factory_reset();");
    const std::size_t erase_registration = commit_block.find("registration_.clear_registration()");
    assert(consume_presence != std::string_view::npos);
    assert(consume_authorization != std::string_view::npos);
    assert(erase_vault != std::string_view::npos);
    assert(erase_registration != std::string_view::npos);
    assert(consume_presence < consume_authorization);
    assert(consume_authorization < erase_vault);
    assert(commit_block.find("current_runtime.state != vault_runtime::State::kUnlocked") !=
        std::string_view::npos);
    assert(commit_block.find("? empty_success(id)") != std::string_view::npos);

    // Superseding security-sensitive session work and recovery-reset takeover
    // both invalidate a pending healthy reset attempt.
    const auto session_block = block_between(
        "if (operation.rfind(\"session.\", 0) == 0)",
        "std::string response;"
    );
    assert(session_block.find("cancel_healthy_factory_reset();") != std::string_view::npos);

    const auto recovery_begin_block = block_between(
        "else if (operation == \"factory_reset.recovery_begin\")",
        "else if (operation == \"factory_reset.recovery_status\")"
    );
    assert(recovery_begin_block.find("cancel_healthy_factory_reset();") != std::string_view::npos);
    assert(recovery_begin_block.find("session::PresenceOperation::kFactoryReset") !=
        std::string_view::npos);

    const auto lock_block = block_between(
        "vault_runtime::Status CanonicalProtocolV2Handler::lock_security_boundary()",
        "void CanonicalProtocolV2Handler::housekeeping"
    );
    assert(lock_block.find("cancel_healthy_factory_reset();") != std::string_view::npos);

    const auto housekeeping_block = block_between(
        "void CanonicalProtocolV2Handler::housekeeping",
        "RecoveryResetDecision CanonicalProtocolV2Handler::recovery_reset_decision"
    );
    assert(housekeeping_block.find("healthy_factory_reset_.expired(now_ms)") !=
        std::string_view::npos);
    assert(housekeeping_block.find("cancel_healthy_factory_reset();") != std::string_view::npos);

    const auto legacy_block = block_between(
        "else if (operation == \"factory_reset\")",
        "else {\n        response = error_response(id, \"unsupported_op\")"
    );
    assert(legacy_block.find("runtime_.factory_reset()") == std::string_view::npos);
    assert(legacy_block.find("registration_.clear_registration()") == std::string_view::npos);
    assert(legacy_block.find("presence_required") != std::string_view::npos);

    const std::size_t disconnect_start = protocol.find("void CanonicalProtocolV2Handler::disconnect()");
    assert(disconnect_start != std::string_view::npos);
    const auto disconnect_block = protocol.substr(disconnect_start);
    assert(disconnect_block.find("cancel_healthy_factory_reset();") != std::string_view::npos);
    assert(disconnect_block.find("cancel_recovery_reset();") != std::string_view::npos);

    return 0;
}
