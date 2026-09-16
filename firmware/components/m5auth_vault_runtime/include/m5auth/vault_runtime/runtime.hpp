#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <vector>

#include "m5auth/vault.hpp"

namespace m5auth::vault_runtime {

inline constexpr std::uint32_t kStorageSchemaVersion = 2;
inline constexpr std::size_t kMaxPersistedCiphertextBytes = 64 * 1024;
inline constexpr std::uint64_t kMillisecondsPerDay = 86'400'000ULL;

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
    kUnsupportedVaultFormat,
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
    // kUnsupportedSchema/kUnsupportedVaultFormat for newer unsupported data.
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
    // True only when Runtime classified the fail-closed persisted state as a
    // structural/reprovision condition for which an explicitly user-confirmed
    // destructive reset is a valid recovery. An unknown newer Vault format is
    // deliberately excluded: firmware must not erase data it cannot interpret.
    bool recovery_reset_allowed{false};
    std::uint32_t storage_schema_version{0};
    std::uint16_t vault_format_version{0};
    std::array<std::uint8_t, vault::kVaultIdBytes> vault_id{};
    std::uint64_t generation{0};
    std::optional<CredentialId> last_used;
};

struct CredentialMetadata {
    CredentialId credential_id{};
    std::string issuer;
    std::string account;
    std::string display_name;
    std::uint16_t manual_order{0};
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
    Status format_for_schema2();
    Status install_encrypted_vault(vault::VaultEnvelope envelope, Vmk vmk);
    Status unlock(Vmk vmk, std::uint64_t now_ms = 0);
    Status lock();

    Status enter_recovery_boundary();
    Status enter_registration_replacement_boundary() {
        return enter_recovery_boundary();
    }
    Status enter_vmk_rekey_boundary() {
        return enter_recovery_boundary();
    }
    Status fatal_security_error();

    Status update_encrypted_vault(
        std::uint64_t expected_generation,
        vault::VaultEnvelope envelope,
        std::uint64_t now_ms = 0,
        bool* automatic_lock_due_after_commit = nullptr
    );

    Status rekey_encrypted_vault(
        std::uint64_t expected_generation,
        vault::VaultEnvelope envelope,
        Vmk vmk,
        std::uint64_t now_ms = 0
    );

    Status metadata(Metadata* metadata) const;
    Status list_credentials(std::vector<CredentialMetadata>* credentials);

    Status with_credential(
        const CredentialId& credential_id,
        const CredentialConsumer& consumer
    );
    Status with_wifi(const WifiConsumer& consumer);

    Status set_last_used(const CredentialId& credential_id);
    Status factory_reset();

    bool unlocked() const;
    bool automatic_lock_due(std::uint64_t now_ms) const;
    std::optional<std::uint8_t> auto_lock_days() const { return auto_lock_days_; }
    std::uint64_t unlocked_since_ms() const { return unlocked_since_ms_; }

private:
    Status reload_after_persistence();
    Status validate_envelope_with_key(
        const vault::VaultEnvelope& envelope,
        const Vmk& vmk,
        std::optional<std::uint8_t>* auto_lock_days = nullptr
    ) const;
    void wipe_vmk();
    void clear_unlock_session_state();
    void begin_unlock_session(
        const std::optional<std::uint8_t>& auto_lock_days,
        std::uint64_t now_ms
    );

    Persistence& persistence_;
    bool initialized_{false};
    bool schema_ready_{false};
    bool has_vault_{false};
    bool recovery_reset_allowed_{false};
    State state_{State::kUnprovisioned};
    vault::VaultEnvelope envelope_{};
    std::optional<CredentialId> last_used_;
    Vmk vmk_{};
    bool vmk_present_{false};
    std::optional<std::uint8_t> auto_lock_days_;
    std::uint64_t unlocked_since_ms_{0};
    bool unlock_session_active_{false};
};

void secure_zero(void* data, std::size_t size);
void wipe_plaintext(vault::VaultPlaintext* plaintext);

}  // namespace m5auth::vault_runtime
