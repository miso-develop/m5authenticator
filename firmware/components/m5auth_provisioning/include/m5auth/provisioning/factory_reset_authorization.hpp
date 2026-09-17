#pragma once

#include <cstddef>
#include <cstdint>
#include <limits>

#include "m5auth/session/protocol_v2.hpp"

namespace m5auth::provisioning {

inline constexpr char kFactoryResetPresenceCapability[] = "factory_reset_presence_required";
inline constexpr char kFactoryResetBeginOperation[] = "factory_reset.begin";
inline constexpr char kFactoryResetStatusOperation[] = "factory_reset.status";
inline constexpr char kFactoryResetCancelOperation[] = "factory_reset.cancel";
inline constexpr char kFactoryResetCommitOperation[] = "factory_reset.commit";

class FactoryResetAuthorization final {
public:
    enum class Check {
        kOk,
        kInactive,
        kMismatch,
        kExpired,
    };

    void begin(const session::AttemptId& attempt_id, std::uint64_t now_ms) {
        attempt_id_ = attempt_id;
        deadline_ms_ = now_ms > std::numeric_limits<std::uint64_t>::max() - session::kAttemptTtlMs
            ? std::numeric_limits<std::uint64_t>::max()
            : now_ms + session::kAttemptTtlMs;
        active_ = true;
    }

    Check check(const session::AttemptId& attempt_id, std::uint64_t now_ms) const {
        if (!active_) return Check::kInactive;
        if (!same_attempt(attempt_id, attempt_id_)) return Check::kMismatch;
        if (now_ms >= deadline_ms_) return Check::kExpired;
        return Check::kOk;
    }

    bool expired(std::uint64_t now_ms) const {
        // Keep the exact deadline observable to the current request so check()
        // can return kExpired and terminally cancel it. Authorization is still
        // unusable at now_ms == deadline_ms_ because check() rejects at >=.
        return active_ && now_ms > deadline_ms_;
    }

    bool active() const {
        return active_;
    }

    const session::AttemptId& attempt_id() const {
        return attempt_id_;
    }

    void cancel() {
        attempt_id_.fill(0);
        deadline_ms_ = 0;
        active_ = false;
    }

    void consume() {
        cancel();
    }

private:
    static bool same_attempt(const session::AttemptId& left, const session::AttemptId& right) {
        std::uint8_t difference = 0;
        for (std::size_t index = 0; index < left.size(); ++index) {
            difference |= static_cast<std::uint8_t>(left[index] ^ right[index]);
        }
        return difference == 0;
    }

    session::AttemptId attempt_id_{};
    std::uint64_t deadline_ms_{0};
    bool active_{false};
};

}  // namespace m5auth::provisioning
