#pragma once

#include <cstddef>
#include <cstdint>
#include <mutex>
#include <string>
#include <string_view>

#include "m5auth/core/metadata.hpp"
#include "m5auth/provisioning/canonical_v2_state.hpp"
#include "m5auth/provisioning/recovery_reset.hpp"
#include "m5auth/provisioning/session_protocol_v2.hpp"
#include "m5auth/registration/registration.hpp"
#include "m5auth/time/time_service.hpp"
#include "m5auth/vault_runtime/runtime.hpp"

namespace m5auth::provisioning {

inline constexpr std::size_t kMaxCanonicalV2MessageBytes = 96 * 1024;

class CanonicalProtocolV2Handler final {
public:
    CanonicalProtocolV2Handler(
        const core::DeviceMetadata& metadata,
        vault_runtime::Runtime& runtime,
        registration::Store& registration,
        time::TimeService& time_service,
        StagedSessionV2Handler& session_handler,
        CanonicalVmkSink& vmk_sink,
        session::protocol_v2::PresenceBinding& recovery_presence,
        std::recursive_mutex& runtime_access_mutex
    );
    ~CanonicalProtocolV2Handler();

    CanonicalProtocolV2Handler(const CanonicalProtocolV2Handler&) = delete;
    CanonicalProtocolV2Handler& operator=(const CanonicalProtocolV2Handler&) = delete;

    std::string handle_line(std::string_view line, std::uint64_t now_ms);
    void disconnect();

    // Called by the production app loop even when stdin is idle. This makes the
    // 30-second Protocol-v2 lifetime proactive: coordinator crypto/context,
    // pending VMK delivery and recovery-reset presence state are wiped without
    // waiting for a later Web request.
    void housekeeping(std::uint64_t now_ms) {
        (void)session_handler_.expire(now_ms);
        (void)vmk_sink_.expire_pending(now_ms);
        if (recovery_reset_active_ && now_ms >= recovery_reset_deadline_ms_) {
            cancel_recovery_reset();
        }
    }

private:
    void cancel_recovery_reset();
    RecoveryResetDecision recovery_reset_decision(
        vault_runtime::Metadata* runtime_metadata,
        registration::Snapshot* registration_snapshot,
        registration::Status* registration_status
    );

    const core::DeviceMetadata& metadata_;
    vault_runtime::Runtime& runtime_;
    registration::Store& registration_;
    time::TimeService& time_service_;
    StagedSessionV2Handler& session_handler_;
    CanonicalVmkSink& vmk_sink_;
    session::protocol_v2::PresenceBinding& recovery_presence_;
    std::recursive_mutex& runtime_access_mutex_;

    session::AttemptId recovery_reset_attempt_id_{};
    std::uint64_t recovery_reset_deadline_ms_{0};
    bool recovery_reset_active_{false};
};

std::string canonical_v2_message_too_large_response();

}  // namespace m5auth::provisioning
