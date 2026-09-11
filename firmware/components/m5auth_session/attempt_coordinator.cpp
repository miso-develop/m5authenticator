#include "m5auth/session/protocol_v2.hpp"

#include <algorithm>
#include <array>
#include <utility>

namespace m5auth::session::protocol_v2 {
namespace {

template <typename Container>
bool all_zero(const Container& value) {
    return std::all_of(value.begin(), value.end(), [](std::uint8_t byte) { return byte == 0; });
}

void secure_zero(void* data, std::size_t size) {
    volatile std::uint8_t* cursor = static_cast<volatile std::uint8_t*>(data);
    while (size-- > 0) *cursor++ = 0;
}

template <typename Container>
void wipe(Container& value) {
    if (!value.empty()) secure_zero(value.data(), value.size() * sizeof(typename Container::value_type));
}

bool context_valid(const BeginContext& context) {
    if (context.device_id.empty() || context.device_id.size() > kMaxDeviceIdBytes) return false;
    if (all_zero(context.registration_id)) return false;
    if (!valid_optional_p256_identity(context.current_brk_public_key) ||
        !valid_optional_p256_identity(context.proposed_brk_public_key)) return false;

    switch (context.operation) {
        case Operation::kTrustedBrowserUnlock:
        case Operation::kVmkRekey:
            return context.registration_epoch > 0 && !is_zero_public_key(context.current_brk_public_key);
        case Operation::kInitialProvisioning:
            return context.registration_epoch == 0 && is_zero_public_key(context.current_brk_public_key) &&
                !is_zero_public_key(context.proposed_brk_public_key);
        case Operation::kRecovery:
        case Operation::kBrowserReplacement:
            return context.registration_epoch > 0 && !is_zero_public_key(context.proposed_brk_public_key);
    }
    return false;
}

bool brk_signature_required(Operation operation) {
    return operation == Operation::kTrustedBrowserUnlock || operation == Operation::kVmkRekey;
}

std::array<std::uint8_t, kHkdfSaltBytes> hkdf_salt(const AttemptDescriptor& descriptor) {
    std::array<std::uint8_t, kHkdfSaltBytes> salt{};
    std::copy(descriptor.attempt_id.begin(), descriptor.attempt_id.end(), salt.begin());
    std::copy(descriptor.challenge.begin(), descriptor.challenge.end(), salt.begin() + kAttemptIdBytes);
    return salt;
}

}  // namespace

AttemptCoordinator::AttemptCoordinator(PresenceBinding& presence) : presence_(presence) {}

AttemptCoordinator::~AttemptCoordinator() {
    cancel();
}

bool AttemptCoordinator::begin(
    const BeginContext& context,
    std::uint64_t now_ms,
    AttemptDescriptor* descriptor
) {
    cancel();
    if (descriptor == nullptr || !context_valid(context)) return false;

    AttemptDescriptor generated{};
    if (!crypto_.begin(now_ms, generated)) return false;

    context_ = context;
    descriptor_ = generated;
    web_public_key_.fill(0);
    transcript_.clear();
    active_ = true;
    state_ = AttemptState::kAwaitingAuthorization;
    *descriptor = generated;
    return true;
}

bool AttemptCoordinator::authorize(
    const P256PublicKey& web_public_key,
    std::span<const std::uint8_t> brk_signature,
    std::uint64_t now_ms
) {
    if (!active_ || state_ != AttemptState::kAwaitingAuthorization ||
        !crypto_.matches_attempt(descriptor_.attempt_id, now_ms)) {
        cancel();
        return false;
    }

    TranscriptInput input{};
    input.operation = context_.operation;
    input.device_id = context_.device_id;
    input.vault_id = context_.vault_id;
    input.expected_generation = context_.expected_generation;
    input.registration_id = context_.registration_id;
    input.registration_epoch = context_.registration_epoch;
    input.attempt_id = descriptor_.attempt_id;
    input.challenge = descriptor_.challenge;
    input.device_ephemeral_public_key = descriptor_.device_public_key;
    input.web_ephemeral_public_key = web_public_key;
    input.current_brk_public_key = context_.current_brk_public_key;
    input.proposed_brk_public_key = context_.proposed_brk_public_key;

    std::vector<std::uint8_t> transcript;
    if (!encode_transcript(input, &transcript)) {
        cancel();
        return false;
    }

    if (brk_signature_required(context_.operation)) {
        if (brk_signature.size() != kBrkSignatureBytes ||
            !crypto_.verify_brk_signature(
                context_.current_brk_public_key,
                transcript,
                brk_signature,
                now_ms
            )) {
            wipe(transcript);
            cancel();
            return false;
        }
    } else if (!brk_signature.empty()) {
        // A supplied signature is never ignored. If a caller elects to bind an
        // additional current-Browser authentication to recovery/replacement,
        // it must be valid or the attempt fails closed.
        if (is_zero_public_key(context_.current_brk_public_key) ||
            brk_signature.size() != kBrkSignatureBytes ||
            !crypto_.verify_brk_signature(
                context_.current_brk_public_key,
                transcript,
                brk_signature,
                now_ms
            )) {
            wipe(transcript);
            cancel();
            return false;
        }
    }

    if (!presence_.begin_presence(
            presence_operation(context_.operation),
            descriptor_.attempt_id,
            now_ms
        )) {
        wipe(transcript);
        cancel();
        return false;
    }

    web_public_key_ = web_public_key;
    transcript_ = std::move(transcript);
    state_ = AttemptState::kAwaitingPresence;
    return true;
}

bool AttemptCoordinator::complete(
    std::span<const std::uint8_t> nonce,
    std::span<const std::uint8_t> ciphertext,
    std::span<const std::uint8_t> tag,
    std::uint64_t now_ms,
    Vmk* vmk
) {
    if (vmk == nullptr) return false;
    vmk->fill(0);
    if (!active_ ||
        (state_ != AttemptState::kAwaitingPresence && state_ != AttemptState::kConfirmed) ||
        !crypto_.matches_attempt(descriptor_.attempt_id, now_ms)) {
        cancel();
        return false;
    }

    if (!presence_.consume_presence(descriptor_.attempt_id, now_ms)) {
        cancel();
        return false;
    }

    auto salt = hkdf_salt(descriptor_);
    const bool opened = crypto_.open_vmk(
        web_public_key_,
        salt,
        transcript_,
        nonce,
        ciphertext,
        tag,
        transcript_,
        now_ms,
        *vmk
    );
    wipe(salt);
    wipe_staged();
    if (!opened) vmk->fill(0);
    return opened;
}

bool AttemptCoordinator::expire(std::uint64_t now_ms) {
    if (!active_) return false;
    const bool crypto_expired = crypto_.expire(now_ms);
    if (crypto_expired || now_ms >= descriptor_.expires_at_ms) {
        cancel();
        return true;
    }
    return false;
}

void AttemptCoordinator::cancel() {
    crypto_.cancel();
    presence_.cancel_presence();
    wipe_staged();
}

AttemptState AttemptCoordinator::state() const {
    if (active_ && state_ == AttemptState::kAwaitingPresence && presence_.presence_confirmed()) {
        return AttemptState::kConfirmed;
    }
    return state_;
}

bool AttemptCoordinator::active() const {
    return active_;
}

const AttemptDescriptor& AttemptCoordinator::descriptor() const {
    return descriptor_;
}

void AttemptCoordinator::wipe_staged() {
    if (!context_.device_id.empty()) secure_zero(context_.device_id.data(), context_.device_id.size());
    context_.device_id.clear();
    wipe(context_.vault_id);
    context_.expected_generation = 0;
    wipe(context_.registration_id);
    context_.registration_epoch = 0;
    wipe(context_.current_brk_public_key);
    wipe(context_.proposed_brk_public_key);
    wipe(descriptor_.attempt_id);
    wipe(descriptor_.challenge);
    wipe(descriptor_.device_public_key);
    descriptor_.expires_at_ms = 0;
    wipe(web_public_key_);
    wipe(transcript_);
    transcript_.clear();
    active_ = false;
    state_ = AttemptState::kIdle;
}

}  // namespace m5auth::session::protocol_v2
