#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace m5auth::vault {

// Format 1 remains the shipped v0.1.0 compatibility default for existing native
// helper call sites and known-answer vectors. Format 2 is the current canonical
// format for new writers and carries the authenticated automatic-lock policy.
inline constexpr std::uint16_t kVaultFormatVersion1 = 1;
inline constexpr std::uint16_t kVaultFormatVersion2 = 2;
inline constexpr std::uint16_t kVaultFormatVersion = kVaultFormatVersion1;
inline constexpr std::uint16_t kCurrentVaultFormatVersion = kVaultFormatVersion2;
inline constexpr std::uint16_t kTargetStorageSchemaVersion = 2;
inline constexpr std::uint16_t kRecoveryPackageVersion = 1;
inline constexpr std::uint16_t kVmkWrapVersion = 1;
inline constexpr std::size_t kVaultIdBytes = 16;
inline constexpr std::size_t kCredentialIdBytes = 16;
inline constexpr std::size_t kVaultNonceBytes = 12;
inline constexpr std::size_t kVaultTagBytes = 16;
inline constexpr std::size_t kVmkBytes = 32;
inline constexpr std::size_t kMaxCredentials = 32;
inline constexpr std::uint8_t kMinAutoLockDays = 1;
inline constexpr std::uint8_t kMaxAutoLockDays = 31;

inline constexpr bool is_supported_vault_format(std::uint16_t version) {
    return version == kVaultFormatVersion1 || version == kVaultFormatVersion2;
}

enum class TotpAlgorithm : std::uint8_t {
    kSha1 = 1,
};

struct CredentialRecord {
    std::array<std::uint8_t, kCredentialIdBytes> credential_id{};
    std::vector<std::uint8_t> secret;
    std::string issuer;
    std::string account;
    std::string display_name;
    TotpAlgorithm algorithm = TotpAlgorithm::kSha1;
    std::uint8_t digits = 6;
    std::uint16_t period_seconds = 30;
    std::uint16_t manual_order = 0;
};

struct WifiRecord {
    std::string ssid;
    std::string password;
};

struct VaultPlaintext {
    std::vector<CredentialRecord> credentials;
    std::optional<WifiRecord> wifi;
    // Present only in Vault Format 2. Format 1 always decodes this as unset.
    std::optional<std::uint8_t> auto_lock_days;
};

struct VaultEnvelope {
    // Keep the legacy default so unchanged Format-1 helper/vector call sites keep
    // their byte-for-byte behavior. Format-2 writers set this explicitly.
    std::uint16_t vault_format_version = kVaultFormatVersion1;
    std::uint16_t storage_schema_version = kTargetStorageSchemaVersion;
    std::array<std::uint8_t, kVaultIdBytes> vault_id{};
    std::uint64_t generation = 0;
    std::array<std::uint8_t, kVaultNonceBytes> nonce{};
    std::vector<std::uint8_t> ciphertext;
    std::array<std::uint8_t, kVaultTagBytes> tag{};
};

struct VmkWrapEnvelope {
    std::uint16_t package_version = kRecoveryPackageVersion;
    std::uint16_t wrap_version = kVmkWrapVersion;
    std::array<std::uint8_t, kVaultIdBytes> vault_id{};
    std::array<std::uint8_t, kVaultNonceBytes> nonce{};
    std::array<std::uint8_t, kVmkBytes> ciphertext{};
    std::array<std::uint8_t, kVaultTagBytes> tag{};
};

bool encode_plaintext(
    const VaultPlaintext& value,
    std::vector<std::uint8_t>& encoded,
    std::uint16_t vault_format_version = kVaultFormatVersion1
);
bool decode_plaintext(
    const std::vector<std::uint8_t>& encoded,
    VaultPlaintext& value,
    std::uint16_t* vault_format_version = nullptr
);

bool build_vault_aad(
    const std::array<std::uint8_t, kVaultIdBytes>& vault_id,
    std::uint64_t generation,
    std::vector<std::uint8_t>& aad,
    std::uint16_t vault_format_version = kVaultFormatVersion1,
    std::uint16_t storage_schema_version = kTargetStorageSchemaVersion
);

bool build_vmk_wrap_aad(
    const std::array<std::uint8_t, kVaultIdBytes>& vault_id,
    std::vector<std::uint8_t>& aad,
    std::uint16_t package_version = kRecoveryPackageVersion,
    std::uint16_t wrap_version = kVmkWrapVersion
);

// Production-facing encryption API. A fresh random 96-bit nonce is generated
// for every invocation; it is never derived from generation. Existing callers
// default to Format 1 for compatibility; Format-2 writers pass version 2.
bool encrypt_vault(
    const std::vector<std::uint8_t>& plaintext,
    const std::array<std::uint8_t, kVmkBytes>& vmk,
    const std::array<std::uint8_t, kVaultIdBytes>& vault_id,
    std::uint64_t generation,
    VaultEnvelope& envelope,
    std::uint16_t vault_format_version = kVaultFormatVersion1
);

// Deterministic nonce injection is exposed only so synthetic public
// interoperability vectors can be reproduced exactly in tests.
bool encrypt_vault_with_nonce(
    const std::vector<std::uint8_t>& plaintext,
    const std::array<std::uint8_t, kVmkBytes>& vmk,
    const std::array<std::uint8_t, kVaultIdBytes>& vault_id,
    std::uint64_t generation,
    const std::array<std::uint8_t, kVaultNonceBytes>& nonce,
    VaultEnvelope& envelope,
    std::uint16_t vault_format_version = kVaultFormatVersion1
);

bool decrypt_vault(
    const VaultEnvelope& envelope,
    const std::array<std::uint8_t, kVmkBytes>& vmk,
    std::vector<std::uint8_t>& plaintext
);

// Reference/native interoperability primitive for Decision #46 vectors. The
// Device runtime does not derive or persist Passphrase KEKs; callers provide a
// transient wrapping key only for cross-implementation verification.
bool wrap_vmk_with_key_and_nonce(
    const std::array<std::uint8_t, kVmkBytes>& vmk,
    const std::array<std::uint8_t, kVmkBytes>& wrapping_key,
    const std::array<std::uint8_t, kVaultIdBytes>& vault_id,
    const std::array<std::uint8_t, kVaultNonceBytes>& nonce,
    VmkWrapEnvelope& envelope
);

bool unwrap_vmk_with_key(
    const VmkWrapEnvelope& envelope,
    const std::array<std::uint8_t, kVmkBytes>& wrapping_key,
    std::array<std::uint8_t, kVmkBytes>& vmk
);

}  // namespace m5auth::vault
