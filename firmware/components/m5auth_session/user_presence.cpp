#include "m5auth/session/session.hpp"

#include <limits>

namespace m5auth::session {
namespace {

bool constant_time_equal(
    std::span<const std::uint8_t> left,
    std::span<const std::uint8_t> right
) {
    if (left.size() != right.size()) return false;
    std::uint8_t difference = 0;
    for (std::size_t index = 0; index < left.size(); ++index) {
        difference |= static_cast<std::uint8_t>(left[index] ^ right[index]);
    }
    return difference == 0;
}

std::uint64_t deadline_from(std::uint64_t now_ms) {
    return now_ms > std::numeric_limits<std::uint64_t>::max() - kAttemptTtlMs
        ? std::numeric_limits<std::uint64_t>::max()
        : now_ms + kAttemptTtlMs;
}

}  // namespace

const char* presence_operation_text(PresenceOperation operation) {
    switch (operation) {
        case PresenceOperation::kTrustedBrowserUnlock:
            return "Browser unlock";
        case PresenceOperation::kInitialProvisioning:
            return "Initial setup";
        case PresenceOperation::kRecovery:
            return "Recovery";
        case PresenceOperation::kBrowserReplacement:
            return "Replace browser";
        case PresenceOperation::kVmkRekey:
            return "Re-key Vault";
        case PresenceOperation::kFactoryReset:
            return "FACTORY RESET";
    }
    return "Security request";
}

bool UserPresenceGate::begin(
    PresenceOperation operation,
    const AttemptId& attempt_id,
    std::uint64_t now_ms,
    std::uint64_t input_generation
) {
    clear();
    operation_ = operation;
    attempt_id_ = attempt_id;
    expires_at_ms_ = deadline_from(now_ms);
    input_generation_at_start_ = input_generation;
    state_ = PresenceState::kAwaiting;
    return true;
}

void UserPresenceGate::observe_input_state(bool pressed) {
    if (state_ != PresenceState::kAwaiting || input_armed_) return;
    if (pressed) {
        neutral_samples_ = 0;
        return;
    }
    if (neutral_samples_ < 2) ++neutral_samples_;
    if (neutral_samples_ >= 2) input_armed_ = true;
}

bool UserPresenceGate::confirm_current(
    std::uint64_t now_ms,
    std::uint64_t input_generation
) {
    if (expire(now_ms) || state_ != PresenceState::kAwaiting) return false;
    if (!input_armed_) return false;
    if (input_generation <= input_generation_at_start_) return false;
    state_ = PresenceState::kConfirmed;
    return true;
}

bool UserPresenceGate::consume_confirmation(
    std::span<const std::uint8_t> attempt_id,
    std::uint64_t now_ms
) {
    if (expire(now_ms) || state_ != PresenceState::kConfirmed) return false;
    if (!constant_time_equal(attempt_id, attempt_id_)) {
        clear();
        return false;
    }
    clear();
    return true;
}

bool UserPresenceGate::expire(std::uint64_t now_ms) {
    if (state_ == PresenceState::kIdle || now_ms < expires_at_ms_) return false;
    clear();
    return true;
}

void UserPresenceGate::cancel() {
    clear();
}

PresenceState UserPresenceGate::state() const {
    return state_;
}

PresenceOperation UserPresenceGate::operation() const {
    return operation_;
}

bool UserPresenceGate::active() const {
    return state_ != PresenceState::kIdle;
}

bool UserPresenceGate::input_armed() const {
    return input_armed_;
}

std::uint64_t UserPresenceGate::expires_at_ms() const {
    return expires_at_ms_;
}

void UserPresenceGate::clear() {
    state_ = PresenceState::kIdle;
    operation_ = PresenceOperation::kTrustedBrowserUnlock;
    attempt_id_.fill(0);
    expires_at_ms_ = 0;
    input_generation_at_start_ = 0;
    neutral_samples_ = 0;
    input_armed_ = false;
}

void PresenceGestureQuarantine::begin(
    std::uint64_t now_ms,
    std::uint32_t click_decision_timeout_ms
) {
    active_ = true;
    release_observed_ = false;
    release_observed_at_ms_ = now_ms;
    click_decision_timeout_ms_ = click_decision_timeout_ms;
}

void PresenceGestureQuarantine::observe(
    bool pressed,
    bool deciding_click_count,
    std::uint64_t now_ms
) {
    if (!active_) return;
    if (pressed) {
        release_observed_ = false;
        return;
    }
    if (!release_observed_) {
        release_observed_ = true;
        release_observed_at_ms_ = now_ms;
        return;
    }
    if (deciding_click_count) return;
    if (now_ms < release_observed_at_ms_) return;
    if (now_ms - release_observed_at_ms_ <= click_decision_timeout_ms_) return;
    cancel();
}

void PresenceGestureQuarantine::cancel() {
    active_ = false;
    release_observed_ = false;
    release_observed_at_ms_ = 0;
    click_decision_timeout_ms_ = 0;
}

}  // namespace m5auth::session
