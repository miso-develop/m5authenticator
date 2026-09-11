#pragma once
#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace m5auth::vault {
inline constexpr std::uint16_t kVaultFormatVersion = 1;
inline constexpr std::uint16_t kTargetStorageSchemaVersion = 2;
inline constexpr std::size_t kVaultIdBytes = 16;
inline constexpr std::size_t kCredentialIdBytes = 16;
inline constexpr std::size_t kVaultNonceBytes = 12;
inline constexpr std::size_t kVaultTagBytes = 16;
inline constexpr std::size_t kVmkBytes = 32;
inline constexpr std::size_t kMaxCredentials = 32;
struct CredentialRecord { std::array<std::uint8_t,kCredentialIdBytes> credential_id{}; std::vector<std::uint8_t> secret; std::string issuer; std::string account; std::string display_name; std::uint8_t digits=6; std::uint16_t period_seconds=30; std::uint16_t manual_order=0; };
struct WifiRecord { std::string ssid; std::string password; };
struct VaultPlaintext { std::vector<CredentialRecord> credentials; std::optional<WifiRecord> wifi; };
struct VaultEnvelope { std::uint16_t vault_format_version=kVaultFormatVersion; std::uint16_t storage_schema_version=kTargetStorageSchemaVersion; std::array<std::uint8_t,kVaultIdBytes> vault_id{}; std::uint64_t generation=0; std::array<std::uint8_t,kVaultNonceBytes> nonce{}; std::vector<std::uint8_t> ciphertext; std::array<std::uint8_t,kVaultTagBytes> tag{}; };
bool encode_plaintext(const VaultPlaintext&, std::vector<std::uint8_t>&);
bool decode_plaintext(const std::vector<std::uint8_t>&, VaultPlaintext&);
bool build_vault_aad(const std::array<std::uint8_t,kVaultIdBytes>&, std::uint64_t, std::vector<std::uint8_t>&, std::uint16_t=kVaultFormatVersion, std::uint16_t=kTargetStorageSchemaVersion);
bool encrypt_vault_with_nonce(const std::vector<std::uint8_t>&, const std::array<std::uint8_t,kVmkBytes>&, const std::array<std::uint8_t,kVaultIdBytes>&, std::uint64_t, const std::array<std::uint8_t,kVaultNonceBytes>&, VaultEnvelope&);
bool decrypt_vault(const VaultEnvelope&, const std::array<std::uint8_t,kVmkBytes>&, std::vector<std::uint8_t>&);
}  // namespace m5auth::vault
