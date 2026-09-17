#include <cassert>
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

    // Terminal consumption makes replay impossible.
    authorization.consume();
    assert(!authorization.active());
    assert(authorization.check(attempt_b, 2002) == FactoryResetAuthorization::Check::kInactive);

    // Cancel/timeout clear the attempt identically and do not leave reusable state.
    authorization.begin(attempt_a, 3000);
    authorization.cancel();
    assert(authorization.check(attempt_a, 3001) == FactoryResetAuthorization::Check::kInactive);
    authorization.begin(attempt_a, 4000);
    assert(authorization.expired(4000 + session::kAttemptTtlMs));
    authorization.cancel();
    assert(!authorization.active());

    return 0;
}
