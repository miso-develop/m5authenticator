#include "m5auth/vault_runtime/runtime.hpp"

#include <limits>
#include <utility>

namespace m5auth::vault_runtime {
namespace {

class ScopedVmkWipe final {
public:
    explicit ScopedVmkWipe(Vmk& vmk) : vmk_(vmk) {}
    ~ScopedVmkWipe() { secure_zero(vmk_.data(), vmk_.size()); }

private:
    Vmk& vmk_;
};

bool same_envelope(
    const vault::VaultEnvelope& left,
    const vault::VaultEnvelope& right
) {
    return left.vault_format_version == right.vault_format_version &&
        left.storage_schema_version == right.storage_schema_version &&
        left.vault_id == right.vault_id &&
        left.generation == right.generation &&
        left.nonce == right.nonce &&
        left.ciphertext == right.ciphertext &&
        left.tag == right.tag;
}

}  // namespace

Status Runtime::enter_vmk_rekey_boundary() {
    if (!initialized_) return Status::kNotReady;
    if (state_ != State::kUnlocked || !vmk_present_ || !has_vault_ ||
        !unlock_session_active_) {
        return Status::kInvalidState;
    }

    // Rekey must destroy the resident VMK immediately, but it is not a fresh
    // unlock. Keep only the bounded non-secret automatic-lock policy/origin so
    // a successful rekey cannot extend the current continuous UNLOCKED lifetime.
    wipe_vmk();
    state_ = State::kLocked;
    return Status::kOk;
}

Status Runtime::rekey_encrypted_vault(
    std::uint64_t expected_generation,
    vault::VaultEnvelope envelope,
    Vmk vmk,
    std::uint64_t now_ms
) {
    ScopedVmkWipe wipe(vmk);
    (void)now_ms;
    if (!initialized_) return Status::kNotReady;
    if (state_ != State::kLocked || vmk_present_ || !has_vault_ ||
        !unlock_session_active_) {
        return Status::kInvalidState;
    }
    if (expected_generation != envelope_.generation ||
        expected_generation == std::numeric_limits<std::uint64_t>::max() ||
        envelope.generation != expected_generation + 1 ||
        envelope.vault_id != envelope_.vault_id) {
        return Status::kGenerationMismatch;
    }
    if (!vault::is_supported_vault_format(envelope.vault_format_version)) {
        return Status::kUnsupportedVaultFormat;
    }
    if (envelope_.vault_format_version == vault::kVaultFormatVersion2 &&
        envelope.vault_format_version == vault::kVaultFormatVersion1) {
        return Status::kInvalidArgument;
    }

    std::optional<std::uint8_t> policy;
    Status status = validate_envelope_with_key(envelope, vmk, &policy);
    if (status != Status::kOk) return status;

    status = persistence_.replace_envelope(expected_generation, envelope);
    if (status != Status::kOk) return status;

    PersistedSnapshot snapshot;
    status = persistence_.load(&snapshot);
    if (status != Status::kOk || !snapshot.schema_ready || !snapshot.has_vault ||
        !same_envelope(snapshot.envelope, envelope)) {
        state_ = State::kError;
        clear_unlock_session_state();
        return status == Status::kOk ? Status::kCorrupt : status;
    }

    envelope_ = std::move(snapshot.envelope);
    last_used_ = snapshot.last_used;
    schema_ready_ = true;
    has_vault_ = true;

    // The old VMK was already destroyed at enter_vmk_rekey_boundary(). Install
    // the new VMK while deliberately retaining unlocked_since_ms_. The candidate
    // authenticated policy becomes effective against that original session T0.
    wipe_vmk();
    vmk_ = vmk;
    vmk_present_ = true;
    auto_lock_days_ = policy;
    state_ = State::kUnlocked;
    recovery_reset_allowed_ = false;
    return Status::kOk;
}

}  // namespace m5auth::vault_runtime
