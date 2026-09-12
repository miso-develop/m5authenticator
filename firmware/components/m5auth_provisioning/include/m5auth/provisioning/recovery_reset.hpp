#pragma once

#include <cstdint>

#include "m5auth/registration/registration.hpp"
#include "m5auth/vault_runtime/runtime.hpp"

namespace m5auth::provisioning {

enum class RecoveryResetDecision : std::uint8_t {
    kNotRequired,
    kRequired,
    kUnavailable,
};

inline RecoveryResetDecision classify_recovery_reset(
    const vault_runtime::Metadata& runtime,
    registration::Status registration_status,
    const registration::Snapshot& registration,
    bool corrupt_registration_recovery_available
) {
    // Runtime explicitly distinguishes structural/unsupported/reprovision
    // failures from generic persistence I/O. Only the former may expose the
    // destructive, presence-gated recovery-reset surface.
    if (runtime.state == vault_runtime::State::kError ||
        runtime.state == vault_runtime::State::kReprovisionRequired) {
        if (!runtime.recovery_reset_allowed) return RecoveryResetDecision::kUnavailable;
        if (registration_status == registration::Status::kIo) {
            return RecoveryResetDecision::kUnavailable;
        }
        if (registration_status == registration::Status::kCorrupt &&
            !corrupt_registration_recovery_available) {
            return RecoveryResetDecision::kUnavailable;
        }
        return RecoveryResetDecision::kRequired;
    }

    if (registration_status == registration::Status::kCorrupt) {
        return corrupt_registration_recovery_available
            ? RecoveryResetDecision::kRequired
            : RecoveryResetDecision::kUnavailable;
    }
    if (registration_status != registration::Status::kOk) {
        return RecoveryResetDecision::kUnavailable;
    }

    if (runtime.has_vault != registration.registration_present) {
        return RecoveryResetDecision::kRequired;
    }
    if (runtime.has_vault && runtime.vault_id != registration.vault_id) {
        return RecoveryResetDecision::kRequired;
    }
    return RecoveryResetDecision::kNotRequired;
}

}  // namespace m5auth::provisioning
