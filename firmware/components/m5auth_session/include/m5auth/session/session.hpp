#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>

namespace m5auth::session {

inline constexpr std::size_t kAttemptIdBytes = 16;
inline constexpr std::size_t kDeviceChallengeBytes = 32;
inline constexpr std::size_t kP256PublicKeyBytes = 65;
inline constexpr std::size_t kSessionKeyBytes = 32;
inline constexpr std::size_t kSessionNonceBytes = 12;
inline constexpr std::size_t kSessionTagBytes = 16;
inline constexpr std::size_t kBrkSignatureBytes = 64;
inline constexpr std::uint64_t kAttemptTtlMs = 30'000;
inline constexpr std::size_t kMaxHkdfContextBytes = 4'096;
inline constexpr std::size_t kMaxTranscriptBytes = 16'384;

using AttemptId = std::array<std::uint8_t, kAttemptIdBytes>;
using DeviceChallenge = std::array<std::uint8_t, kDeviceChallengeBytes>;
using P256PublicKey = std::array<std::uint8_t, kP256PublicKeyBytes>;
using Vmk = std::array<std::uint8_t, kSessionKeyBytes>;

struct AttemptDescriptor {
    AttemptId attempt_id{};
    DeviceChallenge challenge{};
    P256PublicKey device_public_key{};
    std::uint64_t expires_at_ms{0};
};

class DeviceSession {
public:
    DeviceSession();
    ~DeviceSession();

    DeviceSession(const DeviceSession&) = delete;
    DeviceSession& operator=(const DeviceSession&) = delete;
    DeviceSession(DeviceSession&&) = delete;
    DeviceSession& operator=(DeviceSession&&) = delete;

    bool begin(std::uint64_t now_ms, AttemptDescriptor& descriptor);
    bool active(std::uint64_t now_ms) const;
    bool expire(std::uint64_t now_ms);
    void cancel();

    bool matches_attempt(std::span<const std::uint8_t> attempt_id, std::uint64_t now_ms);

    bool verify_brk_signature(
        std::span<const std::uint8_t> brk_public_key,
        std::span<const std::uint8_t> transcript,
        std::span<const std::uint8_t> signature,
        std::uint64_t now_ms
    );

    bool open_vmk(
        std::span<const std::uint8_t> web_public_key,
        std::span<const std::uint8_t> hkdf_salt,
        std::span<const std::uint8_t> hkdf_info,
        std::span<const std::uint8_t> nonce,
        std::span<const std::uint8_t> ciphertext,
        std::span<const std::uint8_t> tag,
        std::span<const std::uint8_t> transcript_aad,
        std::uint64_t now_ms,
        Vmk& vmk
    );

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

enum class PresenceOperation : std::uint8_t {
    kTrustedBrowserUnlock,
    kInitialProvisioning,
    kRecovery,
    kBrowserReplacement,
    kVmkRekey,
};

enum class PresenceState : std::uint8_t {
    kIdle,
    kAwaiting,
    kConfirmed,
};

const char* presence_operation_text(PresenceOperation operation);

class UserPresenceGate {
public:
    bool begin(
        PresenceOperation operation,
        const AttemptId& attempt_id,
        std::uint64_t now_ms,
        std::uint64_t input_generation
    );

    // A request becomes armed only after two consecutive released samples
    // observed after begin(). Requiring two samples prevents a release state
    // sampled just before a concurrent request from arming a pre-existing press.
    void observe_input_state(bool pressed);

    bool confirm_current(std::uint64_t now_ms, std::uint64_t input_generation);
    bool consume_confirmation(
        std::span<const std::uint8_t> attempt_id,
        std::uint64_t now_ms
    );
    bool expire(std::uint64_t now_ms);
    void cancel();

    PresenceState state() const;
    PresenceOperation operation() const;
    bool active() const;
    bool input_armed() const;
    std::uint64_t expires_at_ms() const;

private:
    void clear();

    PresenceState state_{PresenceState::kIdle};
    PresenceOperation operation_{PresenceOperation::kTrustedBrowserUnlock};
    AttemptId attempt_id_{};
    std::uint64_t expires_at_ms_{0};
    std::uint64_t input_generation_at_start_{0};
    std::uint8_t neutral_samples_{0};
    bool input_armed_{false};
};

// Suppresses normal button semantics after a presence-confirmation press until
// that physical gesture has fully completed. M5Unified emits a delayed click
// decision up to getHoldThresh() after release, so clearing immediately on
// release could reinterpret the same authorization gesture as navigation/OTP.
class PresenceGestureQuarantine {
public:
    void begin(std::uint64_t now_ms, std::uint32_t click_decision_timeout_ms);
    void observe(
        bool pressed,
        bool deciding_click_count,
        std::uint64_t now_ms
    );
    void cancel();
    bool active() const { return active_; }

private:
    bool active_{false};
    bool release_observed_{false};
    std::uint64_t release_observed_at_ms_{0};
    std::uint32_t click_decision_timeout_ms_{0};
};

}  // namespace m5auth::session
