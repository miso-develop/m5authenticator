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
inline constexpr std::size_t kHkdfSaltBytes = kAttemptIdBytes + kDeviceChallengeBytes;

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
// BRK identities are represented by all-zero fixed-width fields.
bool encode_transcript(const TranscriptInput& input, std::vector<std::uint8_t>* output);

// Canonical RFC 4648 base64url without padding. Decode rejects '=', whitespace,
// non-url alphabet characters, and non-canonical trailing bits.
std::string base64url_encode(std::span<const std::uint8_t> value);
bool base64url_decode(std::string_view value, std::vector<std::uint8_t>* output);

bool is_zero_public_key(const P256PublicKey& key);
bool valid_optional_p256_identity(const P256PublicKey& key);

struct BeginContext {
    Operation operation{Operation::kTrustedBrowserUnlock};
    std::string device_id;
    VaultId vault_id{};
    std::uint64_t expected_generation{0};
    RegistrationId registration_id{};
    std::uint32_t registration_epoch{0};
    BrkPublicKey current_brk_public_key{};
    BrkPublicKey proposed_brk_public_key{};
};

enum class AttemptState : std::uint8_t {
    kIdle,
    kAwaitingAuthorization,
    kAwaitingPresence,
    kConfirmed,
};

// Adapter implemented by the StickS3 UI model. Keeping the coordinator on this
// interface ensures the same gate that owns the physical button also authorizes
// VMK acceptance; no second software-only confirmation path exists.
class PresenceBinding {
public:
    virtual ~PresenceBinding() = default;
    virtual bool begin_presence(
        PresenceOperation operation,
        const AttemptId& attempt_id,
        std::uint64_t now_ms
    ) = 0;
    virtual bool consume_presence(const AttemptId& attempt_id, std::uint64_t now_ms) = 0;
    virtual void cancel_presence() = 0;
    virtual bool presence_confirmed() const = 0;
};

// Staged Device integration primitive for Task #54. It deliberately does not
// advertise Protocol 2 or mutate registration/Vault persistence; Task #55 owns
// routing these operations into the canonical application state. Every begin()
// supersedes and wipes any previous attempt.
class AttemptCoordinator final {
public:
    explicit AttemptCoordinator(PresenceBinding& presence);
    ~AttemptCoordinator();

    AttemptCoordinator(const AttemptCoordinator&) = delete;
    AttemptCoordinator& operator=(const AttemptCoordinator&) = delete;

    bool begin(
        const BeginContext& context,
        std::uint64_t now_ms,
        AttemptDescriptor* descriptor
    );

    // Web public key and BRK authentication are transcript-bound. Normal
    // Trusted Browser unlock and VMK re-key require the current BRK signature
    // before the Device UI enters the fresh physical-presence state.
    bool authorize(
        const P256PublicKey& web_public_key,
        std::span<const std::uint8_t> brk_signature,
        std::uint64_t now_ms
    );

    // The HKDF contract is attempt_id || challenge as salt and the canonical
    // transcript as both HKDF info and AES-GCM AAD. The Device UI confirmation
    // is one-shot and consumed before cryptographic VMK acceptance.
    bool complete(
        std::span<const std::uint8_t> nonce,
        std::span<const std::uint8_t> ciphertext,
        std::span<const std::uint8_t> tag,
        std::uint64_t now_ms,
        Vmk* vmk
    );

    bool expire(std::uint64_t now_ms);
    void cancel();
    void disconnect() { cancel(); }

    AttemptState state() const;
    bool active() const;
    const AttemptDescriptor& descriptor() const;

private:
    void wipe_staged();

    PresenceBinding& presence_;
    DeviceSession crypto_;
    BeginContext context_{};
    AttemptDescriptor descriptor_{};
    P256PublicKey web_public_key_{};
    std::vector<std::uint8_t> transcript_;
    bool active_{false};
    AttemptState state_{AttemptState::kIdle};
};

}  // namespace m5auth::session::protocol_v2
