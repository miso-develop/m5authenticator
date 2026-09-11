#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>

#include "m5auth/vault.hpp"

namespace m5auth::vault_runtime {

inline constexpr std::uint32_t kStorageSchemaVersion = 2;
inline constexpr std::size_t kMaxPersistedCiphertextBytes = 64 * 1024;

using CredentialId = std::array<std::uint8_t, vault::kCredentialIdBytes>;
using Vmk = std::array<std::uint8_t, vault::kVmkBytes>;

enum class Status {
    kOk,
    kNotReady,
    kUnprovisioned,
    kLocked,
    kInvalidState,
    kInvalidArgument,
    kNotFound,
    kReprovisionRequired,
    kUnsupportedSchema,
    kGenerationMismatch,
    kAuthenticationFailed,
    kCorrupt,
    kIo,
};

const char* status_code(Status status);

enum class State {
    kUnprovisioned,
    kReprovisionRequired,
    kLocked,
    kUnlocked,
    kError,
};

struct PersistedSnapshot {
    bool schema_ready{false};
    bool has_vault{false};
    vault::VaultEnvelope envelope{};
    std::optional<CredentialId> last_used;
};

class Persistence {
public:
    virtual ~Persistence() = default;

    // Returns kOk for a readable Schema 2 partition, kUnprovisioned when no
    // schema exists, kReprovisionRequired for known development Schema 1, and
    // kUnsupportedSchema for a newer schema.
    virtual Status load(PersistedSnapshot* snapshot) = 0;

    // Explicitly destructive reprovision/Factory-Reset preparation. This is
    // never called implicitly by initialize().
    virtual Status format_schema2() = 0;

    // Atomically replace the active encrypted Vault. expected_generation is 0
    // for first install; otherwise it must match the currently active Vault.
    virtual Status replace_envelope(
        std::uint64_t expected_generation,
        const vault::VaultEnvelope& envelope
    ) = 0;

    virtual Status set_last_used(const std::optional<CredentialId>& credential_id) = 0;
    virtual Status erase_all() = 0;
};

// Low-level plaintext-NVS adapter for the target Schema 2 representation.
class NvsPersistence final : public Persistence {
public:
    Status load(PersistedSnapshot* snapshot) override;
    Status format_schema2() override;
    Status replace_envelope(
        std::uint64_t expected_generation,
        const vault::VaultEnvelope& envelope
    ) override;
    Status set_last_used(const std::optional<CredentialId>& credential_id) override;
    Status erase_all() override;
};

// Runtime-facing adapter. It first attempts target Schema 2 and, if that cannot
// be opened, performs a read-only probe using the deliberately public legacy
// development NVS keys. A positively identified Schema 1 returns
// kReprovisionRequired. Unknown/corrupt states retain the original fail-closed
// result; this probe never erases or migrates storage.
class CompatibleNvsPersistence final : public Persistence {
public:
    Status load(PersistedSnapshot* snapshot) override;
    Status format_schema2() override;
    Status replace_envelope(
        std::uint64_t expected_generation,
        const vault::VaultEnvelope& envelope
    ) override;
    Status set_last_used(const std::optional<CredentialId>& credential_id) override;
    Status erase_all() override;

private:
    NvsPersistence schema2_;
};

struct Metadata {
    State state{State::kUnprovisioned};
    bool schema_ready{false};
    bool has_vault{false};
    std::uint32_t storage_schema_version{0};
    std::uint16_t vault_format_version{0};
    std::array<std::uint8_t, vault::kVaultIdBytes> vault_id{};
    std::uint64_t generation{0};
    std::optional<CredentialId> last_used;
};

using CredentialConsumer = std::function<Status(const vault::CredentialRecord&)>;
using WifiConsumer = std::function<Status(const vault::WifiRecord&)>;

class Runtime final {
public:
    explicit Runtime(Persistence& persistence);
    ~Runtime();

    Runtime(const Runtime&) = delete;
    Runtime& operator=(const Runtime&) = delete;
    Runtime(Runtime&&) = delete;
    Runtime& operator=(Runtime&&) = delete;

    Status initialize();

    // Explicitly erase/format the Device-owned partition for Schema 2. This is
    // intended for first provisioning or explicit reprovisioning only.
    Status format_for_schema2();

    // First install validates the authenticated envelope with the transient VMK,
    // persists only encrypted state, wipes the local VMK copy, and remains LOCKED.
    Status install_encrypted_vault(vault::VaultEnvelope envelope, Vmk vmk);

    // VMK is retained only after successful authenticated open of the active Vault.
    Status unlock(Vmk vmk);
    Status lock();

    // Security-root transition boundaries all destroy the resident VMK before
    // subsequent recovery/registration/re-key processing begins. Keeping the
    // entry points distinct makes it difficult for downstream protocol code to
    // accidentally treat an ordinary same-VMK generation update as a re-key.
    Status enter_recovery_boundary();
    Status enter_registration_replacement_boundary() {
        return enter_recovery_boundary();
    }
    Status enter_vmk_rekey_boundary() {
        return enter_recovery_boundary();
    }
    Status fatal_security_error();

    // Same-VMK generation update while UNLOCKED. The active VMK remains resident
    // only if staging/activation succeeds and the new envelope authenticates.
    Status update_encrypted_vault(
        std::uint64_t expected_generation,
        vault::VaultEnvelope envelope
    );

    Status metadata(Metadata* metadata) const;

    // Consumers are synchronous and must not retain references beyond the call.
    // The decrypted Vault is wiped before these methods return.
    Status with_credential(
        const CredentialId& credential_id,
        const CredentialConsumer& consumer
    );
    Status with_wifi(const WifiConsumer& consumer);

    Status set_last_used(const CredentialId& credential_id);
    Status factory_reset();

    bool unlocked() const;

private:
    Status reload_after_persistence();
    Status validate_envelope_with_key(
        const vault::VaultEnvelope& envelope,
        const Vmk& vmk
    ) const;
    void wipe_vmk();

    Persistence& persistence_;
    bool initialized_{false};
    bool schema_ready_{false};
    bool has_vault_{false};
    State state_{State::kUnprovisioned};
    vault::VaultEnvelope envelope_{};
    std::optional<CredentialId> last_used_;
    Vmk vmk_{};
    bool vmk_present_{false};
};

void secure_zero(void* data, std::size_t size);
void wipe_plaintext(vault::VaultPlaintext* plaintext);

}  // namespace m5auth::vault_runtime
