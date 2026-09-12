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
