#include "m5auth/vault_runtime/runtime.hpp"

#include <array>
#include <cassert>
#include <cstdint>
#include <optional>
#include <utility>
#include <vector>

namespace {

using m5auth::vault_runtime::CredentialId;
using m5auth::vault_runtime::Metadata;
using m5auth::vault_runtime::PersistedSnapshot;
using m5auth::vault_runtime::Persistence;
using m5auth::vault_runtime::Runtime;
using m5auth::vault_runtime::Status;
using m5auth::vault_runtime::Vmk;

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

    Status set_last_used(const std::optional<CredentialId>& credential_id) override {
        snapshot.last_used = credential_id;
        return Status::kOk;
    }

    Status erase_all() override {
        snapshot = PersistedSnapshot{};
        return Status::kOk;
    }

    PersistedSnapshot snapshot{};
    Status replace_result{Status::kOk};
};

m5auth::vault::VaultEnvelope make_envelope(
    const Vmk& vmk,
    const std::array<std::uint8_t, m5auth::vault::kVaultIdBytes>& vault_id,
    const CredentialId& credential_id,
    std::uint64_t generation,
    std::uint8_t nonce_start
) {
    m5auth::vault::VaultPlaintext plaintext;
    m5auth::vault::CredentialRecord credential;
    credential.credential_id = credential_id;
    credential.secret = {'S', 'Y', 'N', 'T', 'H', 'E', 'T', 'I', 'C'};
    credential.issuer = "Synthetic";
    credential.account = "rekey-test";
    credential.display_name = "Synthetic Rekey";
    plaintext.credentials.push_back(std::move(credential));

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
    return envelope;
}

}  // namespace

int main() {
    FakePersistence persistence;
    Runtime runtime(persistence);
    assert(runtime.initialize() == Status::kUnprovisioned);
    assert(runtime.format_for_schema2() == Status::kOk);

    const Vmk old_vmk = sequence<m5auth::vault::kVmkBytes>(0x10);
    const Vmk new_vmk = sequence<m5auth::vault::kVmkBytes>(0x50);
    const auto vault_id = sequence<m5auth::vault::kVaultIdBytes>(0x80);
    const CredentialId credential_id = sequence<m5auth::vault::kCredentialIdBytes>(0xa0);
    const auto generation1 = make_envelope(old_vmk, vault_id, credential_id, 1, 0xc0);
    const auto generation2 = make_envelope(new_vmk, vault_id, credential_id, 2, 0xd0);

    assert(runtime.install_encrypted_vault(generation1, old_vmk) == Status::kOk);
    assert(runtime.unlock(old_vmk) == Status::kOk);
    assert(runtime.enter_vmk_rekey_boundary() == Status::kOk);
    assert(!runtime.unlocked());

    Vmk wrong_vmk{};
    wrong_vmk.fill(0xee);
    assert(runtime.rekey_encrypted_vault(1, generation2, wrong_vmk) == Status::kAuthenticationFailed);
    assert(!runtime.unlocked());
    assert(persistence.snapshot.envelope.generation == 1);

    assert(runtime.rekey_encrypted_vault(0, generation2, new_vmk) == Status::kGenerationMismatch);
    assert(!runtime.unlocked());

    persistence.replace_result = Status::kIo;
    assert(runtime.rekey_encrypted_vault(1, generation2, new_vmk) == Status::kIo);
    assert(!runtime.unlocked());
    assert(persistence.snapshot.envelope.generation == 1);

    persistence.replace_result = Status::kOk;
    assert(runtime.rekey_encrypted_vault(1, generation2, new_vmk) == Status::kOk);
    assert(runtime.unlocked());
    Metadata metadata;
    assert(runtime.metadata(&metadata) == Status::kOk);
    assert(metadata.generation == 2);

    assert(runtime.lock() == Status::kOk);
    assert(runtime.unlock(old_vmk) == Status::kAuthenticationFailed);
    assert(runtime.unlock(new_vmk) == Status::kOk);
    return 0;
}
