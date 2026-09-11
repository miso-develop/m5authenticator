#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace m5auth::vault {

inline constexpr std::uint16_t kVaultFormatVersion = 1;
inline constexpr std::uint16_t kTargetStorageSchemaVersion = 2;
inline constexpr std::uint16_t kRecoveryPackageVersion = 1;
inline constexpr std::uint16_t kVmkWrapVersion = 1;
inline constexpr std::size_t kVaultIdBytes = 16;
inline constexpr std::size_t kCredentialIdBytes = 16;
inline constexpr std::size_t kVaultNonceBytes = 12;
inline constexpr std::size_t kVaultTagBytes = 16;
inline constexpr std::size_t kVmkBytes = 32;
inline constexpr std::size_t kMaxCredentials = 32;

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
};

struct VaultEnvelope {
    std::uint16_t vault_format_version = kVaultFormatVersion;
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

bool encode_plaintext(const VaultPlaintext& value, std::vector<std::uint8_t>& encoded);
bool decode_plaintext(const std::vector<std::uint8_t>& encoded, VaultPlaintext& value);

bool build_vault_aad(
    const std::array<std::uint8_t, kVaultIdBytes>& vault_id,
    std::uint64_t generation,
    std::vector<std::uint8_t>& aad,
    std::uint16_t vault_format_version = kVaultFormatVersion,
    std::uint16_t storage_schema_version = kTargetStorageSchemaVersion
);

bool build_vmk_wrap_aad(
    const std::array<std::uint8_t, kVaultIdBytes>& vault_id,
    std::vector<std::uint8_t>& aad,
    std::uint16_t package_version = kRecoveryPackageVersion,
    std::uint16_t wrap_version = kVmkWrapVersion
);

// Production-facing encryption API. A fresh random 96-bit nonce is generated
// for every invocation; it is never derived from generation.
bool encrypt_vault(
    const std::vector<std::uint8_t>& plaintext,
    const std::array<std::uint8_t, kVmkBytes>& vmk,
    const std::array<std::uint8_t, kVaultIdBytes>& vault_id,
    std::uint64_t generation,
    VaultEnvelope& envelope
);

// Deterministic nonce injection is exposed only so synthetic public
// interoperability vectors can be reproduced exactly in tests.
bool encrypt_vault_with_nonce(
    const std::vector<std::uint8_t>& plaintext,
    const std::array<std::uint8_t, kVmkBytes>& vmk,
    const std::array<std::uint8_t, kVaultIdBytes>& vault_id,
    std::uint64_t generation,
    const std::array<std::uint8_t, kVaultNonceBytes>& nonce,
    VaultEnvelope& envelope
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
