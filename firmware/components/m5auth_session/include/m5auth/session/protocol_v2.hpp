#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "m5auth/session/session.hpp"

namespace m5auth::session::protocol_v2 {

inline constexpr std::uint8_t kProtocolVersion = 2;
inline constexpr std::uint8_t kTranscriptVersion = 1;
inline constexpr std::size_t kVaultIdBytes = 16;
inline constexpr std::size_t kRegistrationIdBytes = 16;
inline constexpr std::size_t kMaxDeviceIdBytes = 64;
inline constexpr std::size_t kTranscriptFixedBytes = 360;
inline constexpr std::size_t kMaxEncodedTranscriptBytes = kTranscriptFixedBytes + kMaxDeviceIdBytes;

using VaultId = std::array<std::uint8_t, kVaultIdBytes>;
using RegistrationId = std::array<std::uint8_t, kRegistrationIdBytes>;
using BrkPublicKey = P256PublicKey;

enum class Operation : std::uint8_t {
    kTrustedBrowserUnlock = 1,
    kInitialProvisioning = 2,
    kRecovery = 3,
    kBrowserReplacement = 4,
    kVmkRekey = 5,
};

const char* operation_name(Operation operation);
bool parse_operation(std::string_view value, Operation* operation);
PresenceOperation presence_operation(Operation operation);

struct TranscriptInput {
    Operation operation{Operation::kTrustedBrowserUnlock};
    std::string_view device_id;
    VaultId vault_id{};
    std::uint64_t expected_generation{0};
    RegistrationId registration_id{};
    std::uint32_t registration_epoch{0};
    AttemptId attempt_id{};
    DeviceChallenge challenge{};
    P256PublicKey device_ephemeral_public_key{};
    P256PublicKey web_ephemeral_public_key{};
    BrkPublicKey current_brk_public_key{};
    BrkPublicKey proposed_brk_public_key{};
};

// Fixed-order binary transcript. Numeric fields are big-endian. The only
// variable-width field is device_id, prefixed by one byte. Missing optional
// registration/BRK identities are represented by all-zero fixed-width fields.
bool encode_transcript(const TranscriptInput& input, std::vector<std::uint8_t>* output);

// Canonical RFC 4648 base64url without padding. Decode rejects '=', whitespace,
// non-url alphabet characters, and non-canonical trailing bits.
std::string base64url_encode(std::span<const std::uint8_t> value);
bool base64url_decode(std::string_view value, std::vector<std::uint8_t>* output);

bool is_zero_public_key(const P256PublicKey& key);
bool valid_optional_p256_identity(const P256PublicKey& key);

}  // namespace m5auth::session::protocol_v2
