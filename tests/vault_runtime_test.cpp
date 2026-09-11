#include "m5auth/vault_runtime/runtime.hpp"

#include <array>
#include <cassert>
#include <cstdint>
#include <optional>
#include <string>
#include <utility>
#include <vector>

using m5auth::vault_runtime::CredentialId;
using m5auth::vault_runtime::Metadata;
using m5auth::vault_runtime::PersistedSnapshot;
using m5auth::vault_runtime::Persistence;
using m5auth::vault_runtime::Runtime;
using m5auth::vault_runtime::State;
using m5auth::vault_runtime::Status;
using m5auth::vault_runtime::Vmk;

namespace {

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
        if (load_override.has_value()) return *load_override;
        *output = snapshot;
        return snapshot.schema_ready ? Status::kOk : Status::kUnprovisioned;
    }

    Status format_schema2() override {
        if (format_result != Status::kOk) return format_result;
        snapshot = PersistedSnapshot{};
        snapshot.schema_ready = true;
        return Status::kOk;
    }

    Status replace_envelope(
        std::uint64_t expected_generation,
        const m5auth::vault::VaultEnvelope& envelope
    ) override {
        if (replace_result != Status::kOk) return replace_result;
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

    Status set_last_used(
        const std::optional<CredentialId>& credential_id
    ) override {
        if (last_used_result != Status::kOk) return last_used_result;
        snapshot.last_used = credential_id;
        return Status::kOk;
    }

    Status erase_all() override {
        if (erase_result != Status::kOk) return erase_result;
        snapshot = PersistedSnapshot{};
        return Status::kOk;
    }

    PersistedSnapshot snapshot{};
    std::optional<Status> load_override;
    Status format_result{Status::kOk};
    Status replace_result{Status::kOk};
    Status last_used_result{Status::kOk};
    Status erase_result{Status::kOk};
};

m5auth::vault::VaultPlaintext synthetic_plaintext(const CredentialId& credential_id) {
    m5auth::vault::VaultPlaintext plaintext;
    m5auth::vault::CredentialRecord credential;
    credential.credential_id = credential_id;
    credential.secret = {
        0x53, 0x59, 0x4e, 0x54, 0x48, 0x45, 0x54, 0x49,
        0x43, 0x2d, 0x53, 0x45, 0x43, 0x52, 0x45, 0x54,
    };
    credential.issuer = "Synthetic Issuer";
    credential.account = "synthetic-account";
    credential.display_name = "Synthetic Display";
    credential.algorithm = m5auth::vault::TotpAlgorithm::kSha1;
    credential.digits = 6;
    credential.period_seconds = 30;
    credential.manual_order = 0;
    plaintext.credentials.push_back(std::move(credential));
    plaintext.wifi = m5auth::vault::WifiRecord{
        "synthetic-network",
        "synthetic-network-passphrase",
    };
    return plaintext;
}

m5auth::vault::VaultEnvelope make_envelope(
    const Vmk& vmk,
    const std::array<std::uint8_t, m5auth::vault::kVaultIdBytes>& vault_id,
    const CredentialId& credential_id,
    std::uint64_t generation,
    std::uint8_t nonce_start
) {
    auto plaintext = synthetic_plaintext(credential_id);
    std::vector<std::uint8_t> encoded;
    assert(m5auth::vault::encode_plaintext(plaintext, encoded));
    m5auth::vault_runtime::wipe_plaintext(&plaintext);

    m5auth::vault::VaultEnvelope envelope;
    const auto nonce = sequence<m5auth::vault::kVaultNonceBytes>(nonce_start);
    assert(m5auth::vault::encrypt_vault_with_nonce(
        encoded,
        vmk,
        vault_id,
        generation,
        nonce,
        envelope
    ));
    m5auth::vault_runtime::secure_zero(encoded.data(), encoded.size());
    encoded.clear();
    return envelope;
}

void schema_states_fail_closed() {
    {
        FakePersistence persistence;
        Runtime runtime(persistence);
        assert(runtime.initialize() == Status::kUnprovisioned);
        Metadata metadata;
        assert(runtime.metadata(&metadata) == Status::kOk);
        assert(metadata.state == State::kUnprovisioned);
        assert(!metadata.schema_ready);
    }
    {
        FakePersistence persistence;
        persistence.load_override = Status::kReprovisionRequired;
        Runtime runtime(persistence);
        assert(runtime.initialize() == Status::kReprovisionRequired);
        Metadata metadata;
        assert(runtime.metadata(&metadata) == Status::kOk);
        assert(metadata.state == State::kReprovisionRequired);
    }
    {
        FakePersistence persistence;
        persistence.load_override = Status::kUnsupportedSchema;
        Runtime runtime(persistence);
        assert(runtime.initialize() == Status::kUnsupportedSchema);
        Metadata metadata;
        assert(runtime.metadata(&metadata) == Status::kOk);
        assert(metadata.state == State::kError);
    }
}

void lifecycle_and_lock_gating() {
    FakePersistence persistence;
    Runtime runtime(persistence);
    assert(runtime.initialize() == Status::kUnprovisioned);

    const Vmk vmk = sequence<m5auth::vault::kVmkBytes>(0x10);
    const auto vault_id = sequence<m5auth::vault::kVaultIdBytes>(0x30);
    const CredentialId credential_id =
        sequence<m5auth::vault::kCredentialIdBytes>(0x50);
    auto generation1 = make_envelope(vmk, vault_id, credential_id, 1, 0x70);

    // First installation never auto-formats or silently migrates old storage.
    assert(runtime.install_encrypted_vault(generation1, vmk) == Status::kNotReady);
    assert(runtime.format_for_schema2() == Status::kOk);
    assert(runtime.install_encrypted_vault(generation1, vmk) == Status::kOk);
    assert(!runtime.unlocked());

    Metadata metadata;
    assert(runtime.metadata(&metadata) == Status::kOk);
    assert(metadata.state == State::kLocked);
    assert(metadata.schema_ready);
    assert(metadata.storage_schema_version == 2);
    assert(metadata.vault_format_version == 1);
    assert(metadata.generation == 1);
    assert(metadata.vault_id == vault_id);

    bool credential_called = false;
    assert(runtime.with_credential(
        credential_id,
        [&](const m5auth::vault::CredentialRecord&) {
            credential_called = true;
            return Status::kOk;
        }
    ) == Status::kLocked);
    assert(!credential_called);

    Vmk wrong_vmk{};
    wrong_vmk.fill(0xff);
    assert(runtime.unlock(wrong_vmk) == Status::kAuthenticationFailed);
    assert(!runtime.unlocked());

    assert(runtime.unlock(vmk) == Status::kOk);
    assert(runtime.unlocked());

    credential_called = false;
    assert(runtime.with_credential(
        credential_id,
        [&](const m5auth::vault::CredentialRecord& credential) {
            credential_called = true;
            assert(credential.credential_id == credential_id);
            assert(credential.issuer == "Synthetic Issuer");
            assert(credential.account == "synthetic-account");
            assert(!credential.secret.empty());
            return Status::kOk;
        }
    ) == Status::kOk);
    assert(credential_called);
    assert(persistence.snapshot.last_used == credential_id);

    bool wifi_called = false;
    assert(runtime.with_wifi(
        [&](const m5auth::vault::WifiRecord& wifi) {
            wifi_called = true;
            assert(wifi.ssid == "synthetic-network");
            assert(wifi.password == "synthetic-network-passphrase");
            return Status::kOk;
        }
    ) == Status::kOk);
    assert(wifi_called);

    assert(runtime.lock() == Status::kOk);
    assert(!runtime.unlocked());
    assert(runtime.with_wifi(
        [](const m5auth::vault::WifiRecord&) { return Status::kOk; }
    ) == Status::kLocked);

    assert(runtime.unlock(vmk) == Status::kOk);
    assert(runtime.enter_recovery_boundary() == Status::kOk);
    assert(!runtime.unlocked());
    assert(runtime.with_credential(
        credential_id,
        [](const m5auth::vault::CredentialRecord&) { return Status::kOk; }
    ) == Status::kLocked);
}

void generation_update_is_atomic_and_keeps_vmk() {
    FakePersistence persistence;
    Runtime runtime(persistence);
    assert(runtime.initialize() == Status::kUnprovisioned);
    assert(runtime.format_for_schema2() == Status::kOk);

    const Vmk vmk = sequence<m5auth::vault::kVmkBytes>(0x11);
    const auto vault_id = sequence<m5auth::vault::kVaultIdBytes>(0x31);
    const CredentialId credential_id =
        sequence<m5auth::vault::kCredentialIdBytes>(0x51);
    const auto generation1 = make_envelope(vmk, vault_id, credential_id, 1, 0x71);
    const auto generation2 = make_envelope(vmk, vault_id, credential_id, 2, 0x81);
    const auto generation3 = make_envelope(vmk, vault_id, credential_id, 3, 0x91);

    assert(runtime.install_encrypted_vault(generation1, vmk) == Status::kOk);
    assert(runtime.unlock(vmk) == Status::kOk);

    persistence.replace_result = Status::kIo;
    assert(runtime.update_encrypted_vault(1, generation2) == Status::kIo);
    assert(runtime.unlocked());
    Metadata metadata;
    assert(runtime.metadata(&metadata) == Status::kOk);
    assert(metadata.generation == 1);
    assert(persistence.snapshot.envelope.generation == 1);

    persistence.replace_result = Status::kOk;
    assert(runtime.update_encrypted_vault(0, generation2) == Status::kGenerationMismatch);
    assert(runtime.update_encrypted_vault(1, generation3) == Status::kGenerationMismatch);
    assert(runtime.update_encrypted_vault(1, generation2) == Status::kOk);
    assert(runtime.unlocked());
    assert(runtime.metadata(&metadata) == Status::kOk);
    assert(metadata.generation == 2);

    auto tampered = generation3;
    tampered.tag[0] ^= 0x01;
    assert(runtime.update_encrypted_vault(2, tampered) == Status::kAuthenticationFailed);
    assert(runtime.unlocked());
    assert(runtime.metadata(&metadata) == Status::kOk);
    assert(metadata.generation == 2);
}

void reboot_starts_locked_and_factory_reset_wipes_state() {
    FakePersistence persistence;
    const Vmk vmk = sequence<m5auth::vault::kVmkBytes>(0x12);
    const auto vault_id = sequence<m5auth::vault::kVaultIdBytes>(0x32);
    const CredentialId credential_id =
        sequence<m5auth::vault::kCredentialIdBytes>(0x52);
    const auto envelope = make_envelope(vmk, vault_id, credential_id, 1, 0x72);

    {
        Runtime first_boot(persistence);
        assert(first_boot.initialize() == Status::kUnprovisioned);
        assert(first_boot.format_for_schema2() == Status::kOk);
        assert(first_boot.install_encrypted_vault(envelope, vmk) == Status::kOk);
        assert(first_boot.unlock(vmk) == Status::kOk);
        assert(first_boot.unlocked());
    }

    Runtime second_boot(persistence);
    assert(second_boot.initialize() == Status::kOk);
    assert(!second_boot.unlocked());
    Metadata metadata;
    assert(second_boot.metadata(&metadata) == Status::kOk);
    assert(metadata.state == State::kLocked);
    assert(metadata.generation == 1);

    assert(second_boot.unlock(vmk) == Status::kOk);
    assert(second_boot.fatal_security_error() == Status::kOk);
    assert(!second_boot.unlocked());
    assert(second_boot.metadata(&metadata) == Status::kOk);
    assert(metadata.state == State::kError);

    // A reboot-equivalent initialize wipes any runtime key and reloads ciphertext.
    assert(second_boot.initialize() == Status::kOk);
    assert(!second_boot.unlocked());
    assert(second_boot.factory_reset() == Status::kOk);
    assert(second_boot.metadata(&metadata) == Status::kOk);
    assert(metadata.state == State::kUnprovisioned);
    assert(!metadata.schema_ready);
    assert(!metadata.has_vault);
}

void explicit_plaintext_wipe_clears_secret_fields() {
    const CredentialId credential_id =
        sequence<m5auth::vault::kCredentialIdBytes>(0x53);
    auto plaintext = synthetic_plaintext(credential_id);
    assert(!plaintext.credentials.empty());
    assert(!plaintext.credentials[0].secret.empty());
    assert(plaintext.wifi.has_value());

    m5auth::vault_runtime::wipe_plaintext(&plaintext);
    assert(plaintext.credentials.empty());
    assert(!plaintext.wifi.has_value());
}

}  // namespace

int main() {
    schema_states_fail_closed();
    lifecycle_and_lock_gating();
    generation_update_is_atomic_and_keeps_vmk();
    reboot_starts_locked_and_factory_reset_wipes_state();
    explicit_plaintext_wipe_clears_secret_fields();
    return 0;
}
