#include "m5auth/provisioning/canonical_v2_state.hpp"

#include <algorithm>
#include <limits>

namespace m5auth::provisioning {
namespace {

template <typename Container>
bool all_zero(const Container& value) {
    return std::all_of(value.begin(), value.end(), [](std::uint8_t byte) { return byte == 0; });
}

class ScopedVmkWipe final {
public:
    explicit ScopedVmkWipe(session::Vmk& vmk) : vmk_(vmk) {}
    ~ScopedVmkWipe() { vault_runtime::secure_zero(vmk_.data(), vmk_.size()); }

    ScopedVmkWipe(const ScopedVmkWipe&) = delete;
    ScopedVmkWipe& operator=(const ScopedVmkWipe&) = delete;

private:
    session::Vmk& vmk_;
};

void wipe_context(session::protocol_v2::BeginContext* context) {
    if (context == nullptr) return;
    if (!context->device_id.empty()) {
        vault_runtime::secure_zero(context->device_id.data(), context->device_id.size());
    }
    context->device_id.clear();
    context->vault_id.fill(0);
    context->expected_generation = 0;
    context->registration_id.fill(0);
    context->registration_epoch = 0;
    context->current_brk_public_key.fill(0);
    context->proposed_brk_public_key.fill(0);
    context->operation = session::protocol_v2::Operation::kTrustedBrowserUnlock;
}

bool envelope_matches_pending(
    const vault::VaultEnvelope& envelope,
    const session::protocol_v2::BeginContext& context,
    std::uint64_t generation
) {
    return envelope.vault_format_version == vault::kVaultFormatVersion &&
        envelope.storage_schema_version == vault::kTargetStorageSchemaVersion &&
        envelope.vault_id == context.vault_id &&
        envelope.generation == generation &&
        !envelope.ciphertext.empty();
}

}  // namespace

bool CanonicalBindingSource::snapshot(SessionV2DeviceSnapshot* output) const {
    std::lock_guard<std::recursive_mutex> access(runtime_access_mutex_);
    if (output == nullptr) return false;

    vault_runtime::Metadata runtime_metadata{};
    registration::Snapshot registration_snapshot{};
    if (runtime_.metadata(&runtime_metadata) != vault_runtime::Status::kOk ||
        registration_.snapshot(&registration_snapshot) != registration::Status::kOk) {
        return false;
    }

    if (runtime_metadata.has_vault != registration_snapshot.registration_present) {
        return false;
    }
    if (runtime_metadata.has_vault &&
        runtime_metadata.vault_id != registration_snapshot.vault_id) {
        return false;
    }

    SessionV2DeviceSnapshot result{};
    result.device_id = registration::device_id_text(registration_snapshot.device_id);
    if (result.device_id.empty()) return false;

    result.vault_present = runtime_metadata.has_vault;
    if (runtime_metadata.has_vault) {
        result.vault_id = runtime_metadata.vault_id;
        result.generation = runtime_metadata.generation;
    }
    result.registration_present = registration_snapshot.registration_present;
    if (registration_snapshot.registration_present) {
        result.registration_id = registration_snapshot.registration_id;
        result.registration_epoch = registration_snapshot.epoch;
        result.brk_public_key = registration_snapshot.brk_public_key;
    }
    *output = std::move(result);
    return true;
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

bool CanonicalVmkSink::prepare_attempt(
    const session::protocol_v2::BeginContext& context
) {
    std::lock_guard<std::recursive_mutex> access(runtime_access_mutex_);
    cancel_pending();

    vault_runtime::Metadata metadata{};
    if (runtime_.metadata(&metadata) != vault_runtime::Status::kOk) return false;

    switch (context.operation) {
        case session::protocol_v2::Operation::kInitialProvisioning:
            return !metadata.has_vault &&
                (metadata.state == vault_runtime::State::kUnprovisioned ||
                 metadata.state == vault_runtime::State::kReprovisionRequired);

        case session::protocol_v2::Operation::kTrustedBrowserUnlock:
            return metadata.has_vault && metadata.state == vault_runtime::State::kLocked;

        case session::protocol_v2::Operation::kRecovery:
            if (!metadata.has_vault) {
                return metadata.state == vault_runtime::State::kUnprovisioned ||
                    metadata.state == vault_runtime::State::kReprovisionRequired;
            }
            return runtime_.enter_registration_replacement_boundary() == vault_runtime::Status::kOk;

        case session::protocol_v2::Operation::kBrowserReplacement:
            return metadata.has_vault &&
                runtime_.enter_registration_replacement_boundary() == vault_runtime::Status::kOk;

        case session::protocol_v2::Operation::kVmkRekey:
            if (!metadata.has_vault || !runtime_.unlocked()) return false;
            return runtime_.enter_vmk_rekey_boundary() == vault_runtime::Status::kOk;
    }
    return false;
}

bool CanonicalVmkSink::install_vmk(
    const session::protocol_v2::BeginContext& context,
    const session::Vmk& vmk
) {
    std::lock_guard<std::recursive_mutex> access(runtime_access_mutex_);
    cancel_pending();

    switch (context.operation) {
        case session::protocol_v2::Operation::kTrustedBrowserUnlock:
            return runtime_.unlock(vmk) == vault_runtime::Status::kOk;

        case session::protocol_v2::Operation::kRecovery: {
            vault_runtime::Metadata metadata{};
            if (runtime_.metadata(&metadata) != vault_runtime::Status::kOk) return false;
            if (!metadata.has_vault) {
                if ((metadata.state != vault_runtime::State::kUnprovisioned &&
                     metadata.state != vault_runtime::State::kReprovisionRequired) ||
                    context.expected_generation == 0 ||
                    context.registration_epoch != 1 ||
                    !all_zero(context.current_brk_public_key)) {
                    return false;
                }
                pending_vmk_ = vmk;
                pending_context_ = context;
                pending_ = true;
                deadline_armed_ = false;
                pending_expires_at_ms_ = 0;
                return true;
            }
            if (context.registration_epoch == 0) return false;
            if (runtime_.unlock(vmk) != vault_runtime::Status::kOk) return false;
            const registration::Status registration_status = registration_.replace(
                context.vault_id,
                context.registration_epoch - 1,
                context.registration_id,
                context.registration_epoch,
                context.proposed_brk_public_key
            );
            if (registration_status != registration::Status::kOk) {
                (void)runtime_.lock();
                return false;
            }
            return true;
        }

        case session::protocol_v2::Operation::kBrowserReplacement: {
            if (context.registration_epoch == 0) return false;
            if (runtime_.unlock(vmk) != vault_runtime::Status::kOk) return false;
            const registration::Status registration_status = registration_.replace(
                context.vault_id,
                context.registration_epoch - 1,
                context.registration_id,
                context.registration_epoch,
                context.proposed_brk_public_key
            );
            if (registration_status != registration::Status::kOk) {
                (void)runtime_.lock();
                return false;
            }
            return true;
        }

        case session::protocol_v2::Operation::kInitialProvisioning:
        case session::protocol_v2::Operation::kVmkRekey:
            pending_vmk_ = vmk;
            pending_context_ = context;
            pending_ = true;
            deadline_armed_ = false;
            pending_expires_at_ms_ = 0;
            return true;
    }
    return false;
}

void CanonicalVmkSink::arm_pending_deadline(std::uint64_t now_ms) {
    std::lock_guard<std::recursive_mutex> access(runtime_access_mutex_);
    if (!pending_) return;
    deadline_armed_ = true;
    pending_expires_at_ms_ = now_ms >
            std::numeric_limits<std::uint64_t>::max() - kPendingVaultVmkTtlMs
        ? std::numeric_limits<std::uint64_t>::max()
        : now_ms + kPendingVaultVmkTtlMs;
}

bool CanonicalVmkSink::expire_pending(std::uint64_t now_ms) {
    std::lock_guard<std::recursive_mutex> access(runtime_access_mutex_);
    if (!pending_ || !deadline_armed_ || now_ms < pending_expires_at_ms_) return false;
    cancel_pending();
    return true;
}

void CanonicalVmkSink::cancel_pending() {
    std::lock_guard<std::recursive_mutex> access(runtime_access_mutex_);
    vault_runtime::secure_zero(pending_vmk_.data(), pending_vmk_.size());
    wipe_context(&pending_context_);
    pending_ = false;
    deadline_armed_ = false;
    pending_expires_at_ms_ = 0;
}

bool CanonicalVmkSink::pending_valid(
    session::protocol_v2::Operation operation,
    std::uint64_t now_ms
) {
    std::lock_guard<std::recursive_mutex> access(runtime_access_mutex_);
    (void)expire_pending(now_ms);
    return pending_ && deadline_armed_ && pending_context_.operation == operation;
}

bool CanonicalVmkSink::install_initial_vault(
    vault::VaultEnvelope envelope,
    std::uint64_t now_ms
) {
    std::lock_guard<std::recursive_mutex> access(runtime_access_mutex_);
    if (!pending_valid(session::protocol_v2::Operation::kInitialProvisioning, now_ms) ||
        pending_context_.expected_generation != 0 ||
        pending_context_.registration_epoch != 0 ||
        all_zero(pending_context_.registration_id) ||
        !envelope_matches_pending(envelope, pending_context_, 1)) {
        cancel_pending();
        return false;
    }

    const auto context = pending_context_;
    session::Vmk vmk = pending_vmk_;
    ScopedVmkWipe wipe_vmk(vmk);

    vault_runtime::Status status = runtime_.format_for_schema2();
    if (status == vault_runtime::Status::kOk) {
        status = runtime_.install_encrypted_vault(envelope, vmk);
    }
    if (status == vault_runtime::Status::kOk) {
        status = runtime_.unlock(vmk);
    }
    if (status != vault_runtime::Status::kOk) {
        (void)runtime_.factory_reset();
        cancel_pending();
        return false;
    }

    const registration::Status registration_status = registration_.install_initial(
        context.vault_id,
        context.registration_id,
        1,
        context.proposed_brk_public_key
    );
    if (registration_status != registration::Status::kOk) {
        (void)runtime_.factory_reset();
        cancel_pending();
        return false;
    }

    cancel_pending();
    return true;
}

bool CanonicalVmkSink::install_recovered_vault(
    vault::VaultEnvelope envelope,
    std::uint64_t now_ms
) {
    std::lock_guard<std::recursive_mutex> access(runtime_access_mutex_);
    if (!pending_valid(session::protocol_v2::Operation::kRecovery, now_ms) ||
        pending_context_.expected_generation == 0 ||
        pending_context_.registration_epoch != 1 ||
        !all_zero(pending_context_.current_brk_public_key) ||
        all_zero(pending_context_.registration_id) ||
        !envelope_matches_pending(
            envelope,
            pending_context_,
            pending_context_.expected_generation
        )) {
        cancel_pending();
        return false;
    }

    const auto context = pending_context_;
    session::Vmk vmk = pending_vmk_;
    ScopedVmkWipe wipe_vmk(vmk);

    vault_runtime::Status status = runtime_.format_for_schema2();
    if (status == vault_runtime::Status::kOk) {
        status = runtime_.install_encrypted_vault(envelope, vmk);
    }
    if (status == vault_runtime::Status::kOk) {
        status = runtime_.unlock(vmk);
    }
    if (status != vault_runtime::Status::kOk) {
        (void)runtime_.factory_reset();
        cancel_pending();
        return false;
    }

    const registration::Status registration_status = registration_.install_initial(
        context.vault_id,
        context.registration_id,
        1,
        context.proposed_brk_public_key
    );
    if (registration_status != registration::Status::kOk) {
        (void)runtime_.factory_reset();
        cancel_pending();
        return false;
    }

    cancel_pending();
    return true;
}

bool CanonicalVmkSink::install_rekeyed_vault(
    std::uint64_t expected_generation,
    vault::VaultEnvelope envelope,
    std::uint64_t now_ms
) {
    std::lock_guard<std::recursive_mutex> access(runtime_access_mutex_);
    if (!pending_valid(session::protocol_v2::Operation::kVmkRekey, now_ms) ||
        expected_generation != pending_context_.expected_generation ||
        expected_generation == std::numeric_limits<std::uint64_t>::max() ||
        !envelope_matches_pending(envelope, pending_context_, expected_generation + 1)) {
        cancel_pending();
        return false;
    }

    session::Vmk vmk = pending_vmk_;
    ScopedVmkWipe wipe_vmk(vmk);
    const vault_runtime::Status status = runtime_.rekey_encrypted_vault(
        expected_generation,
        std::move(envelope),
        vmk
    );
    cancel_pending();
    return status == vault_runtime::Status::kOk;
}

bool CanonicalVmkSink::has_pending_vmk() const {
    std::lock_guard<std::recursive_mutex> access(runtime_access_mutex_);
    return pending_;
}

session::protocol_v2::Operation CanonicalVmkSink::pending_operation() const {
    std::lock_guard<std::recursive_mutex> access(runtime_access_mutex_);
    return pending_context_.operation;
}

}  // namespace m5auth::provisioning
