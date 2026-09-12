#include <cassert>

#include "m5auth/provisioning/recovery_reset.hpp"

int main() {
    using namespace m5auth;
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

    return 0;
}
