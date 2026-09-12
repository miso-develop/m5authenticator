#include "m5auth/vault_runtime/runtime.hpp"

#include <algorithm>
#include <limits>
#include <string>
#include <utility>
#include <vector>

namespace m5auth::vault_runtime {
namespace {

class ScopedKeyWipe final {
public:
    explicit ScopedKeyWipe(Vmk& key) : key_(key) {}
    ~ScopedKeyWipe() { secure_zero(key_.data(), key_.size()); }

private:
    Vmk& key_;
};

void wipe_string(std::string* value) {
    if (value == nullptr) return;
    if (!value->empty()) secure_zero(value->data(), value->size());
    value->clear();
}

void wipe_bytes(std::vector<std::uint8_t>* value) {
    if (value == nullptr) return;
    if (!value->empty()) secure_zero(value->data(), value->size());
    value->clear();
}

bool valid_envelope_framing(const vault::VaultEnvelope& envelope) {
    return envelope.vault_format_version == vault::kVaultFormatVersion &&
           envelope.storage_schema_version == vault::kTargetStorageSchemaVersion &&
           envelope.generation != 0 &&
           !envelope.ciphertext.empty() &&
           envelope.ciphertext.size() <= kMaxPersistedCiphertextBytes;
}

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

bool explicit_reset_recovery_status(Status status) {
    return status == Status::kCorrupt ||
           status == Status::kUnsupportedSchema ||
           status == Status::kReprovisionRequired;
}

}  // namespace

const char* status_code(Status status) {
    switch (status) {
        case Status::kOk: return "ok";
        case Status::kNotReady: return "not_ready";
        case Status::kUnprovisioned: return "unprovisioned";
        case Status::kLocked: return "locked";
        case Status::kInvalidState: return "invalid_state";
        case Status::kInvalidArgument: return "invalid_argument";
        case Status::kNotFound: return "not_found";
        case Status::kReprovisionRequired: return "reprovision_required";
        case Status::kUnsupportedSchema: return "unsupported_schema";
        case Status::kGenerationMismatch: return "generation_mismatch";
        case Status::kAuthenticationFailed: return "authentication_failed";
        case Status::kCorrupt: return "corrupt";
        case Status::kIo: return "io_error";
    }
    return "runtime_error";
}

void secure_zero(void* data, std::size_t size) {
    volatile auto* cursor = static_cast<volatile std::uint8_t*>(data);
    while (size-- > 0) *cursor++ = 0;
}

void wipe_plaintext(vault::VaultPlaintext* plaintext) {
    if (plaintext == nullptr) return;

    for (auto& credential : plaintext->credentials) {
        credential.credential_id.fill(0);
        wipe_bytes(&credential.secret);
        wipe_string(&credential.issuer);
        wipe_string(&credential.account);
        wipe_string(&credential.display_name);
        credential.algorithm = vault::TotpAlgorithm::kSha1;
        credential.digits = 0;
        credential.period_seconds = 0;
        credential.manual_order = 0;
    }
    plaintext->credentials.clear();

    if (plaintext->wifi.has_value()) {
        wipe_string(&plaintext->wifi->ssid);
        wipe_string(&plaintext->wifi->password);
        plaintext->wifi.reset();
    }
}

Runtime::Runtime(Persistence& persistence) : persistence_(persistence) {}

Runtime::~Runtime() {
    wipe_vmk();
}

void Runtime::wipe_vmk() {
    secure_zero(vmk_.data(), vmk_.size());
    vmk_present_ = false;
}

Status Runtime::initialize() {
    wipe_vmk();
    initialized_ = true;
    schema_ready_ = false;
    has_vault_ = false;
    recovery_reset_allowed_ = false;
    envelope_ = vault::VaultEnvelope{};
    last_used_.reset();
    state_ = State::kUnprovisioned;

    PersistedSnapshot snapshot;
    const Status status = persistence_.load(&snapshot);
    if (status == Status::kUnprovisioned) return status;
    if (status == Status::kReprovisionRequired) {
        state_ = State::kReprovisionRequired;
        recovery_reset_allowed_ = true;
        return status;
    }
    if (status != Status::kOk) {
        state_ = State::kError;
        recovery_reset_allowed_ = explicit_reset_recovery_status(status);
        return status;
    }
    if (!snapshot.schema_ready) {
        state_ = State::kError;
        recovery_reset_allowed_ = true;
        return Status::kCorrupt;
    }

    schema_ready_ = true;
    last_used_ = snapshot.last_used;
    if (!snapshot.has_vault) return Status::kUnprovisioned;
    if (!valid_envelope_framing(snapshot.envelope)) {
        state_ = State::kError;
        recovery_reset_allowed_ = true;
        return Status::kCorrupt;
    }

    has_vault_ = true;
    envelope_ = std::move(snapshot.envelope);
    state_ = State::kLocked;
    return Status::kOk;
}

Status Runtime::reload_after_persistence() {
    PersistedSnapshot snapshot;
    const Status status = persistence_.load(&snapshot);
    if (status != Status::kOk || !snapshot.schema_ready) {
        state_ = State::kError;
        recovery_reset_allowed_ = status == Status::kOk || explicit_reset_recovery_status(status);
        wipe_vmk();
        return status == Status::kOk ? Status::kCorrupt : status;
    }

    recovery_reset_allowed_ = false;
    schema_ready_ = true;
    last_used_ = snapshot.last_used;
    has_vault_ = snapshot.has_vault;
    if (!has_vault_) {
        envelope_ = vault::VaultEnvelope{};
        state_ = State::kUnprovisioned;
        wipe_vmk();
        return Status::kOk;
    }
    if (!valid_envelope_framing(snapshot.envelope)) {
        state_ = State::kError;
        recovery_reset_allowed_ = true;
        wipe_vmk();
        return Status::kCorrupt;
    }

    envelope_ = std::move(snapshot.envelope);
    state_ = State::kLocked;
    wipe_vmk();
    return Status::kOk;
}

Status Runtime::format_for_schema2() {
    if (!initialized_) return Status::kNotReady;

    wipe_vmk();
    const Status status = persistence_.format_schema2();
    if (status != Status::kOk) {
        state_ = State::kError;
        recovery_reset_allowed_ = explicit_reset_recovery_status(status);
        return status;
    }
    return reload_after_persistence();
}

Status Runtime::validate_envelope_with_key(
    const vault::VaultEnvelope& envelope,
    const Vmk& vmk
) const {
    if (!valid_envelope_framing(envelope)) return Status::kInvalidArgument;

    std::vector<std::uint8_t> encoded_plaintext;
    if (!vault::decrypt_vault(envelope, vmk, encoded_plaintext)) {
        wipe_bytes(&encoded_plaintext);
        return Status::kAuthenticationFailed;
    }

    vault::VaultPlaintext plaintext;
    const bool decoded = vault::decode_plaintext(encoded_plaintext, plaintext);
    wipe_bytes(&encoded_plaintext);
    wipe_plaintext(&plaintext);
    return decoded ? Status::kOk : Status::kCorrupt;
}

Status Runtime::install_encrypted_vault(vault::VaultEnvelope envelope, Vmk vmk) {
    ScopedKeyWipe wipe(vmk);
    if (!initialized_) return Status::kNotReady;
    if (!schema_ready_) return Status::kNotReady;
    if (state_ != State::kUnprovisioned || has_vault_) return Status::kInvalidState;

    Status status = validate_envelope_with_key(envelope, vmk);
    if (status != Status::kOk) return status;

    status = persistence_.replace_envelope(0, envelope);
    if (status != Status::kOk) return status;

    status = reload_after_persistence();
    if (status != Status::kOk || !has_vault_ || !same_envelope(envelope_, envelope)) {
        state_ = State::kError;
        recovery_reset_allowed_ = status == Status::kOk || explicit_reset_recovery_status(status);
        wipe_vmk();
        return status == Status::kOk ? Status::kCorrupt : status;
    }
    return Status::kOk;
}

Status Runtime::unlock(Vmk vmk) {
    ScopedKeyWipe wipe(vmk);
    if (!initialized_) return Status::kNotReady;
    if (state_ != State::kLocked || !has_vault_) return Status::kInvalidState;

    const Status status = validate_envelope_with_key(envelope_, vmk);
    if (status != Status::kOk) return status;

    wipe_vmk();
    vmk_ = vmk;
    vmk_present_ = true;
    state_ = State::kUnlocked;
    recovery_reset_allowed_ = false;
    return Status::kOk;
}

Status Runtime::lock() {
    if (!initialized_) return Status::kNotReady;
    wipe_vmk();
    if (state_ == State::kError) return Status::kInvalidState;
    state_ = has_vault_ ? State::kLocked : State::kUnprovisioned;
    return Status::kOk;
}

Status Runtime::enter_recovery_boundary() {
    if (!initialized_) return Status::kNotReady;
    wipe_vmk();
    if (state_ == State::kError) return Status::kInvalidState;
    state_ = has_vault_ ? State::kLocked : State::kUnprovisioned;
    return Status::kOk;
}

Status Runtime::fatal_security_error() {
    if (!initialized_) return Status::kNotReady;
    wipe_vmk();
    state_ = State::kError;
    recovery_reset_allowed_ = true;
    return Status::kOk;
}

Status Runtime::update_encrypted_vault(
    std::uint64_t expected_generation,
    vault::VaultEnvelope envelope
) {
    if (!initialized_) return Status::kNotReady;
    if (state_ != State::kUnlocked || !vmk_present_ || !has_vault_) return Status::kLocked;
    if (expected_generation != envelope_.generation ||
        expected_generation == std::numeric_limits<std::uint64_t>::max() ||
        envelope.generation != expected_generation + 1 ||
        envelope.vault_id != envelope_.vault_id) {
        return Status::kGenerationMismatch;
    }

    Status status = validate_envelope_with_key(envelope, vmk_);
    if (status != Status::kOk) return status;

    status = persistence_.replace_envelope(expected_generation, envelope);
    if (status != Status::kOk) return status;

    PersistedSnapshot snapshot;
    status = persistence_.load(&snapshot);
    if (status != Status::kOk || !snapshot.schema_ready || !snapshot.has_vault ||
        !same_envelope(snapshot.envelope, envelope)) {
        fatal_security_error();
        return status == Status::kOk ? Status::kCorrupt : status;
    }

    envelope_ = std::move(snapshot.envelope);
    last_used_ = snapshot.last_used;
    schema_ready_ = true;
    has_vault_ = true;
    recovery_reset_allowed_ = false;
    state_ = State::kUnlocked;
    return Status::kOk;
}

Status Runtime::metadata(Metadata* metadata_output) const {
    if (metadata_output == nullptr) return Status::kInvalidArgument;
    if (!initialized_) return Status::kNotReady;

    Metadata result;
    result.state = state_;
    result.schema_ready = schema_ready_;
    result.has_vault = has_vault_;
    result.recovery_reset_allowed = recovery_reset_allowed_;
    result.storage_schema_version = schema_ready_ ? kStorageSchemaVersion : 0;
    result.last_used = last_used_;
    if (has_vault_) {
        result.vault_format_version = envelope_.vault_format_version;
        result.vault_id = envelope_.vault_id;
        result.generation = envelope_.generation;
    }
    *metadata_output = result;
    return Status::kOk;
}

Status Runtime::with_credential(
    const CredentialId& credential_id,
    const CredentialConsumer& consumer
) {
    if (!initialized_) return Status::kNotReady;
    if (state_ != State::kUnlocked || !vmk_present_ || !has_vault_) return Status::kLocked;
    if (!consumer) return Status::kInvalidArgument;

    std::vector<std::uint8_t> encoded_plaintext;
    if (!vault::decrypt_vault(envelope_, vmk_, encoded_plaintext)) {
        wipe_bytes(&encoded_plaintext);
        fatal_security_error();
        return Status::kAuthenticationFailed;
    }

    vault::VaultPlaintext plaintext;
    if (!vault::decode_plaintext(encoded_plaintext, plaintext)) {
        wipe_bytes(&encoded_plaintext);
        wipe_plaintext(&plaintext);
        fatal_security_error();
        return Status::kCorrupt;
    }
    wipe_bytes(&encoded_plaintext);

    auto found = std::find_if(
        plaintext.credentials.begin(),
        plaintext.credentials.end(),
        [&credential_id](const vault::CredentialRecord& credential) {
            return credential.credential_id == credential_id;
        }
    );
    if (found == plaintext.credentials.end()) {
        wipe_plaintext(&plaintext);
        return Status::kNotFound;
    }

    Status status = consumer(*found);
    if (status == Status::kOk) {
        const Status last_used_status = persistence_.set_last_used(credential_id);
        if (last_used_status == Status::kOk) last_used_ = credential_id;
        else status = last_used_status;
    }
    wipe_plaintext(&plaintext);
    return status;
}

Status Runtime::with_wifi(const WifiConsumer& consumer) {
    if (!initialized_) return Status::kNotReady;
    if (state_ != State::kUnlocked || !vmk_present_ || !has_vault_) return Status::kLocked;
    if (!consumer) return Status::kInvalidArgument;

    std::vector<std::uint8_t> encoded_plaintext;
    if (!vault::decrypt_vault(envelope_, vmk_, encoded_plaintext)) {
        wipe_bytes(&encoded_plaintext);
        fatal_security_error();
        return Status::kAuthenticationFailed;
    }

    vault::VaultPlaintext plaintext;
    if (!vault::decode_plaintext(encoded_plaintext, plaintext)) {
        wipe_bytes(&encoded_plaintext);
        wipe_plaintext(&plaintext);
        fatal_security_error();
        return Status::kCorrupt;
    }
    wipe_bytes(&encoded_plaintext);

    if (!plaintext.wifi.has_value()) {
        wipe_plaintext(&plaintext);
        return Status::kNotFound;
    }

    const Status status = consumer(*plaintext.wifi);
    wipe_plaintext(&plaintext);
    return status;
}

Status Runtime::set_last_used(const CredentialId& credential_id) {
    if (!initialized_) return Status::kNotReady;
    if (state_ != State::kUnlocked || !vmk_present_ || !has_vault_) return Status::kLocked;

    std::vector<std::uint8_t> encoded_plaintext;
    if (!vault::decrypt_vault(envelope_, vmk_, encoded_plaintext)) {
        wipe_bytes(&encoded_plaintext);
        fatal_security_error();
        return Status::kAuthenticationFailed;
    }
    vault::VaultPlaintext plaintext;
    if (!vault::decode_plaintext(encoded_plaintext, plaintext)) {
        wipe_bytes(&encoded_plaintext);
        wipe_plaintext(&plaintext);
        fatal_security_error();
        return Status::kCorrupt;
    }
    wipe_bytes(&encoded_plaintext);

    const bool exists = std::any_of(
        plaintext.credentials.begin(),
        plaintext.credentials.end(),
        [&credential_id](const vault::CredentialRecord& credential) {
            return credential.credential_id == credential_id;
        }
    );
    wipe_plaintext(&plaintext);
    if (!exists) return Status::kNotFound;

    const Status status = persistence_.set_last_used(credential_id);
    if (status == Status::kOk) last_used_ = credential_id;
    return status;
}

Status Runtime::factory_reset() {
    if (!initialized_) return Status::kNotReady;

    wipe_vmk();
    const Status status = persistence_.erase_all();
    if (status != Status::kOk) {
        state_ = State::kError;
        recovery_reset_allowed_ = false;
        return status;
    }

    schema_ready_ = false;
    has_vault_ = false;
    recovery_reset_allowed_ = false;
    envelope_ = vault::VaultEnvelope{};
    last_used_.reset();
    state_ = State::kUnprovisioned;
    return Status::kOk;
}

bool Runtime::unlocked() const {
    return initialized_ && state_ == State::kUnlocked && vmk_present_;
}

}  // namespace m5auth::vault_runtime
