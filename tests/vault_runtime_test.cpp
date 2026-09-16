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

m5auth::vault::VaultPlaintext synthetic_plaintext(
    const CredentialId& credential_id,
    std::optional<std::uint8_t> auto_lock_days = std::nullopt
) {
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
    plaintext.auto_lock_days = auto_lock_days;
    return plaintext;
}

m5auth::vault::VaultEnvelope make_envelope(
    const Vmk& vmk,
    const std::array<std::uint8_t, m5auth::vault::kVaultIdBytes>& vault_id,
    const CredentialId& credential_id,
    std::uint64_t generation,
    std::uint8_t nonce_start,
    std::uint16_t vault_format = m5auth::vault::kVaultFormatVersion1,
    std::optional<std::uint8_t> auto_lock_days = std::nullopt
) {
    auto plaintext = synthetic_plaintext(credential_id, auto_lock_days);
    std::vector<std::uint8_t> encoded;
    assert(m5auth::vault::encode_plaintext(plaintext, encoded, vault_format));
    m5auth::vault_runtime::wipe_plaintext(&plaintext);

    m5auth::vault::VaultEnvelope envelope;
    const auto nonce = sequence<m5auth::vault::kVaultNonceBytes>(nonce_start);
    assert(m5auth::vault::encrypt_vault_with_nonce(
        encoded,
        vmk,
        vault_id,
        generation,
        nonce,
        envelope,
        vault_format
    ));
    m5auth::vault_runtime::secure_zero(encoded.data(), encoded.size());
    encoded.clear();
    return envelope;
}

m5auth::vault::VaultEnvelope make_authenticated_malformed_f2_envelope(
    const Vmk& vmk,
    const std::array<std::uint8_t, m5auth::vault::kVaultIdBytes>& vault_id,
    const CredentialId& credential_id,
    std::uint64_t generation,
    std::uint8_t nonce_start
) {
    auto plaintext = synthetic_plaintext(credential_id, 1);
    std::vector<std::uint8_t> encoded;
    assert(m5auth::vault::encode_plaintext(
        plaintext,
        encoded,
        m5auth::vault::kVaultFormatVersion2
    ));
    m5auth::vault_runtime::wipe_plaintext(&plaintext);
    assert(encoded.size() >= 2);
    // PT2 terminates with auto_lock_present=1, auto_lock_days=1. Replacing the
    // authenticated day byte with 0 keeps AEAD valid while making PT2 invalid.
    assert(encoded[encoded.size() - 2] == 1);
    assert(encoded.back() == 1);
    encoded.back() = 0;

    m5auth::vault::VaultEnvelope envelope;
    const auto nonce = sequence<m5auth::vault::kVaultNonceBytes>(nonce_start);
    assert(m5auth::vault::encrypt_vault_with_nonce(
        encoded,
        vmk,
        vault_id,
        generation,
        nonce,
        envelope,
        m5auth::vault::kVaultFormatVersion2
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
    {
        FakePersistence persistence;
        persistence.snapshot.schema_ready = true;
        persistence.snapshot.has_vault = true;
        persistence.snapshot.envelope.vault_format_version = 3;
        persistence.snapshot.envelope.storage_schema_version = 2;
        persistence.snapshot.envelope.generation = 1;
        persistence.snapshot.envelope.ciphertext = {0x01};
        Runtime runtime(persistence);
        assert(runtime.initialize() == Status::kUnsupportedVaultFormat);
        Metadata metadata;
        assert(runtime.metadata(&metadata) == Status::kOk);
        assert(metadata.state == State::kError);
        assert(!metadata.recovery_reset_allowed);
        assert(persistence.snapshot.has_vault);
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
    assert(runtime.unlock(wrong_vmk, 10'000) == Status::kAuthenticationFailed);
    assert(!runtime.unlocked());

    assert(runtime.unlock(vmk, 10'000) == Status::kOk);
    assert(runtime.unlocked());
    assert(!runtime.auto_lock_days().has_value());
    assert(runtime.unlocked_since_ms() == 10'000);
    assert(!runtime.automatic_lock_due(UINT64_C(1000000000000)));

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
    assert(runtime.unlocked_since_ms() == 10'000);

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
    assert(runtime.unlocked_since_ms() == 10'000);

    assert(runtime.lock() == Status::kOk);
    assert(!runtime.unlocked());
    assert(!runtime.auto_lock_days().has_value());
    assert(runtime.with_wifi(
        [](const m5auth::vault::WifiRecord&) { return Status::kOk; }
    ) == Status::kLocked);

    assert(runtime.unlock(vmk, 20'000) == Status::kOk);
    assert(runtime.unlocked_since_ms() == 20'000);
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
    assert(runtime.unlock(vmk, 5'000) == Status::kOk);

    persistence.replace_result = Status::kIo;
    assert(runtime.update_encrypted_vault(1, generation2, 6'000) == Status::kIo);
    assert(runtime.unlocked());
    Metadata metadata;
    assert(runtime.metadata(&metadata) == Status::kOk);
    assert(metadata.generation == 1);
    assert(persistence.snapshot.envelope.generation == 1);
    assert(runtime.unlocked_since_ms() == 5'000);

    persistence.replace_result = Status::kOk;
    assert(runtime.update_encrypted_vault(0, generation2, 6'000) == Status::kGenerationMismatch);
    assert(runtime.update_encrypted_vault(1, generation3, 6'000) == Status::kGenerationMismatch);
    assert(runtime.update_encrypted_vault(1, generation2, 6'000) == Status::kOk);
    assert(runtime.unlocked());
    assert(runtime.metadata(&metadata) == Status::kOk);
    assert(metadata.generation == 2);
    assert(runtime.unlocked_since_ms() == 5'000);

    auto tampered = generation3;
    tampered.tag[0] ^= 0x01;
    assert(runtime.update_encrypted_vault(2, tampered, 7'000) == Status::kAuthenticationFailed);
    assert(runtime.unlocked());
    assert(runtime.metadata(&metadata) == Status::kOk);
    assert(metadata.generation == 2);
    assert(runtime.unlocked_since_ms() == 5'000);
}

void format_transition_matrix_and_legacy_boot() {
    const Vmk vmk = sequence<m5auth::vault::kVmkBytes>(0x14);
    const auto vault_id = sequence<m5auth::vault::kVaultIdBytes>(0x34);
    const CredentialId credential_id =
        sequence<m5auth::vault::kCredentialIdBytes>(0x54);

    FakePersistence persistence;
    persistence.snapshot.schema_ready = true;
    persistence.snapshot.has_vault = true;
    persistence.snapshot.envelope = make_envelope(
        vmk, vault_id, credential_id, 1, 0x74,
        m5auth::vault::kVaultFormatVersion1
    );

    Runtime runtime(persistence);
    assert(runtime.initialize() == Status::kOk);
    Metadata metadata;
    assert(runtime.metadata(&metadata) == Status::kOk);
    assert(metadata.state == State::kLocked);
    assert(metadata.vault_format_version == m5auth::vault::kVaultFormatVersion1);
    assert(metadata.generation == 1);

    const std::uint64_t unlock_start = 42'000;
    assert(runtime.unlock(vmk, unlock_start) == Status::kOk);
    assert(!runtime.auto_lock_days().has_value());

    // F1 -> F1 remains valid for an active legacy Vault.
    const auto generation2_f1 = make_envelope(
        vmk, vault_id, credential_id, 2, 0x84,
        m5auth::vault::kVaultFormatVersion1
    );
    assert(runtime.update_encrypted_vault(1, generation2_f1, unlock_start + 100) == Status::kOk);
    assert(runtime.metadata(&metadata) == Status::kOk);
    assert(metadata.vault_format_version == m5auth::vault::kVaultFormatVersion1);
    assert(runtime.unlocked_since_ms() == unlock_start);

    // F1 -> F2 upgrades through the normal canonical generation transaction.
    const auto generation3_f2 = make_envelope(
        vmk, vault_id, credential_id, 3, 0x94,
        m5auth::vault::kVaultFormatVersion2,
        31
    );
    bool due_after_commit = true;
    assert(runtime.update_encrypted_vault(
        2, generation3_f2, unlock_start + 200, &due_after_commit
    ) == Status::kOk);
    assert(!due_after_commit);
    assert(runtime.auto_lock_days() == std::optional<std::uint8_t>(31));
    assert(runtime.metadata(&metadata) == Status::kOk);
    assert(metadata.vault_format_version == m5auth::vault::kVaultFormatVersion2);
    assert(runtime.unlocked_since_ms() == unlock_start);

    // F2 -> F1 is rejected even when generation/vault_id/AEAD are otherwise valid.
    const auto generation4_f1 = make_envelope(
        vmk, vault_id, credential_id, 4, 0xa4,
        m5auth::vault::kVaultFormatVersion1
    );
    assert(runtime.update_encrypted_vault(
        3, generation4_f1, unlock_start + 300
    ) == Status::kInvalidArgument);
    assert(runtime.metadata(&metadata) == Status::kOk);
    assert(metadata.generation == 3);
    assert(metadata.vault_format_version == m5auth::vault::kVaultFormatVersion2);
    assert(runtime.auto_lock_days() == std::optional<std::uint8_t>(31));

    // F2 -> F2 remains valid.
    const auto generation4_f2 = make_envelope(
        vmk, vault_id, credential_id, 4, 0xb4,
        m5auth::vault::kVaultFormatVersion2,
        std::nullopt
    );
    assert(runtime.update_encrypted_vault(
        3, generation4_f2, unlock_start + 400
    ) == Status::kOk);
    assert(!runtime.auto_lock_days().has_value());
    assert(runtime.metadata(&metadata) == Status::kOk);
    assert(metadata.generation == 4);
    assert(metadata.vault_format_version == m5auth::vault::kVaultFormatVersion2);

    // Unknown newer formats fail closed without mutating the committed envelope.
    auto unknown = make_envelope(
        vmk, vault_id, credential_id, 5, 0xc4,
        m5auth::vault::kVaultFormatVersion2,
        1
    );
    unknown.vault_format_version = 3;
    assert(runtime.update_encrypted_vault(4, unknown, unlock_start + 500) ==
           Status::kUnsupportedVaultFormat);
    assert(runtime.metadata(&metadata) == Status::kOk);
    assert(metadata.generation == 4);

    // Reboot preserves the Format-2 envelope but starts LOCKED as before.
    Runtime rebooted(persistence);
    assert(rebooted.initialize() == Status::kOk);
    assert(!rebooted.unlocked());
    assert(rebooted.metadata(&metadata) == Status::kOk);
    assert(metadata.state == State::kLocked);
    assert(metadata.vault_format_version == m5auth::vault::kVaultFormatVersion2);
    assert(metadata.generation == 4);
}

void malformed_authenticated_format2_is_rejected() {
    FakePersistence persistence;
    Runtime runtime(persistence);
    assert(runtime.initialize() == Status::kUnprovisioned);
    assert(runtime.format_for_schema2() == Status::kOk);

    const Vmk vmk = sequence<m5auth::vault::kVmkBytes>(0x15);
    const auto vault_id = sequence<m5auth::vault::kVaultIdBytes>(0x35);
    const CredentialId credential_id =
        sequence<m5auth::vault::kCredentialIdBytes>(0x55);
    const auto malformed = make_authenticated_malformed_f2_envelope(
        vmk, vault_id, credential_id, 1, 0x75
    );

    // Installation validates authenticated PT2 before committing it.
    assert(runtime.install_encrypted_vault(malformed, vmk) == Status::kCorrupt);
    assert(!persistence.snapshot.has_vault);
}

void automatic_lock_boundaries_and_activity_do_not_extend_session() {
    FakePersistence persistence;
    Runtime runtime(persistence);
    assert(runtime.initialize() == Status::kUnprovisioned);
    assert(runtime.format_for_schema2() == Status::kOk);

    const Vmk vmk = sequence<m5auth::vault::kVmkBytes>(0x16);
    const auto vault_id = sequence<m5auth::vault::kVaultIdBytes>(0x36);
    const CredentialId credential_id =
        sequence<m5auth::vault::kCredentialIdBytes>(0x56);
    const auto one_day = make_envelope(
        vmk, vault_id, credential_id, 1, 0x76,
        m5auth::vault::kVaultFormatVersion2,
        1
    );
    assert(runtime.install_encrypted_vault(one_day, vmk) == Status::kOk);

    const std::uint64_t start = 123'456;
    assert(runtime.unlock(vmk, start) == Status::kOk);
    assert(runtime.auto_lock_days() == std::optional<std::uint8_t>(1));
    assert(!runtime.automatic_lock_due(start + m5auth::vault_runtime::kMillisecondsPerDay - 1));

    // Normal secret access/navigation state updates never alter the unlock origin.
    assert(runtime.with_credential(
        credential_id,
        [](const m5auth::vault::CredentialRecord&) { return Status::kOk; }
    ) == Status::kOk);
    assert(runtime.set_last_used(credential_id) == Status::kOk);
    assert(runtime.with_wifi(
        [](const m5auth::vault::WifiRecord&) { return Status::kOk; }
    ) == Status::kOk);
    assert(runtime.unlocked_since_ms() == start);
    assert(runtime.automatic_lock_due(start + m5auth::vault_runtime::kMillisecondsPerDay));

    // Protocol housekeeping executes the actual shared Lock boundary; Runtime's
    // lock primitive verifies the resulting credential/VMK gating and cleanup.
    assert(runtime.lock() == Status::kOk);
    assert(!runtime.unlocked());
    assert(runtime.with_credential(
        credential_id,
        [](const m5auth::vault::CredentialRecord&) { return Status::kOk; }
    ) == Status::kLocked);

    // A fresh re-unlock gets a new continuous-lifetime origin.
    const std::uint64_t second_start = start + 2 * m5auth::vault_runtime::kMillisecondsPerDay;
    assert(runtime.unlock(vmk, second_start) == Status::kOk);
    assert(runtime.unlocked_since_ms() == second_start);
    assert(!runtime.automatic_lock_due(
        second_start + m5auth::vault_runtime::kMillisecondsPerDay - 1
    ));

    // Upgrade policy to the maximum boundary and verify exact 31-day expiry.
    const auto thirty_one_days = make_envelope(
        vmk, vault_id, credential_id, 2, 0x86,
        m5auth::vault::kVaultFormatVersion2,
        31
    );
    bool due_after_commit = true;
    assert(runtime.update_encrypted_vault(
        1, thirty_one_days, second_start + 1, &due_after_commit
    ) == Status::kOk);
    assert(!due_after_commit);
    assert(!runtime.automatic_lock_due(
        second_start + 31 * m5auth::vault_runtime::kMillisecondsPerDay - 1
    ));
    assert(runtime.automatic_lock_due(
        second_start + 31 * m5auth::vault_runtime::kMillisecondsPerDay
    ));
}

void committed_setting_changes_use_original_unlock_origin() {
    FakePersistence persistence;
    Runtime runtime(persistence);
    assert(runtime.initialize() == Status::kUnprovisioned);
    assert(runtime.format_for_schema2() == Status::kOk);

    const Vmk vmk = sequence<m5auth::vault::kVmkBytes>(0x17);
    const auto vault_id = sequence<m5auth::vault::kVaultIdBytes>(0x37);
    const CredentialId credential_id =
        sequence<m5auth::vault::kCredentialIdBytes>(0x57);
    const auto disabled = make_envelope(
        vmk, vault_id, credential_id, 1, 0x77,
        m5auth::vault::kVaultFormatVersion2,
        std::nullopt
    );
    assert(runtime.install_encrypted_vault(disabled, vmk) == Status::kOk);

    const std::uint64_t start = 10'000;
    assert(runtime.unlock(vmk, start) == Status::kOk);
    assert(!runtime.auto_lock_days().has_value());

    // Disabled -> 31 days applies from the original start, not update time.
    const auto days31 = make_envelope(
        vmk, vault_id, credential_id, 2, 0x87,
        m5auth::vault::kVaultFormatVersion2,
        31
    );
    bool due_after_commit = true;
    const std::uint64_t two_days_later = start + 2 * m5auth::vault_runtime::kMillisecondsPerDay;
    assert(runtime.update_encrypted_vault(
        1, days31, two_days_later, &due_after_commit
    ) == Status::kOk);
    assert(!due_after_commit);
    assert(runtime.unlocked_since_ms() == start);

    // 31 -> 1 day is already expired relative to the unchanged start.
    const auto days1 = make_envelope(
        vmk, vault_id, credential_id, 3, 0x97,
        m5auth::vault::kVaultFormatVersion2,
        1
    );
    assert(runtime.update_encrypted_vault(
        2, days1, two_days_later, &due_after_commit
    ) == Status::kOk);
    assert(due_after_commit);
    assert(runtime.unlocked_since_ms() == start);
    assert(runtime.auto_lock_days() == std::optional<std::uint8_t>(1));

    // A failed candidate disable does not weaken the committed one-day policy.
    const auto disabled4 = make_envelope(
        vmk, vault_id, credential_id, 4, 0xa7,
        m5auth::vault::kVaultFormatVersion2,
        std::nullopt
    );
    persistence.replace_result = Status::kIo;
    due_after_commit = false;
    assert(runtime.update_encrypted_vault(
        3, disabled4, two_days_later, &due_after_commit
    ) == Status::kIo);
    assert(!due_after_commit);
    assert(runtime.auto_lock_days() == std::optional<std::uint8_t>(1));
    assert(runtime.automatic_lock_due(two_days_later));

    // A successfully committed disable cancels the deadline without resetting
    // the original session timestamp.
    persistence.replace_result = Status::kOk;
    assert(runtime.update_encrypted_vault(
        3, disabled4, two_days_later, &due_after_commit
    ) == Status::kOk);
    assert(!due_after_commit);
    assert(!runtime.auto_lock_days().has_value());
    assert(runtime.unlocked_since_ms() == start);
    assert(!runtime.automatic_lock_due(UINT64_C(1000000000000)));
}

void reboot_starts_locked_and_factory_reset_wipes_state() {
    FakePersistence persistence;
    const Vmk vmk = sequence<m5auth::vault::kVmkBytes>(0x12);
    const auto vault_id = sequence<m5auth::vault::kVaultIdBytes>(0x32);
    const CredentialId credential_id =
        sequence<m5auth::vault::kCredentialIdBytes>(0x52);
    const auto envelope = make_envelope(
        vmk, vault_id, credential_id, 1, 0x72,
        m5auth::vault::kVaultFormatVersion2,
        31
    );

    {
        Runtime first_boot(persistence);
        assert(first_boot.initialize() == Status::kUnprovisioned);
        assert(first_boot.format_for_schema2() == Status::kOk);
        assert(first_boot.install_encrypted_vault(envelope, vmk) == Status::kOk);
        assert(first_boot.unlock(vmk, 50'000) == Status::kOk);
        assert(first_boot.unlocked());
        assert(first_boot.auto_lock_days() == std::optional<std::uint8_t>(31));
    }

    Runtime second_boot(persistence);
    assert(second_boot.initialize() == Status::kOk);
    assert(!second_boot.unlocked());
    assert(!second_boot.auto_lock_days().has_value());
    Metadata metadata;
    assert(second_boot.metadata(&metadata) == Status::kOk);
    assert(metadata.state == State::kLocked);
    assert(metadata.generation == 1);
    assert(metadata.vault_format_version == m5auth::vault::kVaultFormatVersion2);

    assert(second_boot.unlock(vmk, 60'000) == Status::kOk);
    assert(second_boot.auto_lock_days() == std::optional<std::uint8_t>(31));
    assert(second_boot.fatal_security_error() == Status::kOk);
    assert(!second_boot.unlocked());
    assert(second_boot.metadata(&metadata) == Status::kOk);
    assert(metadata.state == State::kError);

    // A reboot-equivalent initialize wipes any runtime key and policy state and
    // reloads only authenticated ciphertext.
    assert(second_boot.initialize() == Status::kOk);
    assert(!second_boot.unlocked());
    assert(!second_boot.auto_lock_days().has_value());
    assert(second_boot.factory_reset() == Status::kOk);
    assert(second_boot.metadata(&metadata) == Status::kOk);
    assert(metadata.state == State::kUnprovisioned);
    assert(!metadata.schema_ready);
    assert(!metadata.has_vault);
}

void explicit_plaintext_wipe_clears_secret_fields_and_policy() {
    const CredentialId credential_id =
        sequence<m5auth::vault::kCredentialIdBytes>(0x53);
    auto plaintext = synthetic_plaintext(credential_id, 7);
    assert(!plaintext.credentials.empty());
    assert(!plaintext.credentials[0].secret.empty());
    assert(plaintext.wifi.has_value());
    assert(plaintext.auto_lock_days.has_value());

    m5auth::vault_runtime::wipe_plaintext(&plaintext);
    assert(plaintext.credentials.empty());
    assert(!plaintext.wifi.has_value());
    assert(!plaintext.auto_lock_days.has_value());
}

}  // namespace

int main() {
    schema_states_fail_closed();
    lifecycle_and_lock_gating();
    generation_update_is_atomic_and_keeps_vmk();
    format_transition_matrix_and_legacy_boot();
    malformed_authenticated_format2_is_rejected();
    automatic_lock_boundaries_and_activity_do_not_extend_session();
    committed_setting_changes_use_original_unlock_origin();
    reboot_starts_locked_and_factory_reset_wipes_state();
    explicit_plaintext_wipe_clears_secret_fields_and_policy();
    return 0;
}
