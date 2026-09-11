#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

#include "m5auth/core/metadata.hpp"
#include "m5auth/provisioning/canonical_v2_state.hpp"
#include "m5auth/provisioning/session_protocol_v2.hpp"
#include "m5auth/registration/registration.hpp"
#include "m5auth/time/time_service.hpp"
#include "m5auth/vault_runtime/runtime.hpp"

namespace m5auth::provisioning {

// 64 KiB authenticated Vault ciphertext expands to about 87 KiB base64url;
// keep a fixed, auditable upper bound for the complete NDJSON request.
inline constexpr std::size_t kMaxCanonicalV2MessageBytes = 96 * 1024;

class CanonicalProtocolV2Handler final {
public:
    CanonicalProtocolV2Handler(
        const core::DeviceMetadata& metadata,
        vault_runtime::Runtime& runtime,
        registration::Store& registration,
        time::TimeService& time_service,
        StagedSessionV2Handler& session_handler,
        CanonicalVmkSink& vmk_sink
    );
    ~CanonicalProtocolV2Handler();

    CanonicalProtocolV2Handler(const CanonicalProtocolV2Handler&) = delete;
    CanonicalProtocolV2Handler& operator=(const CanonicalProtocolV2Handler&) = delete;

    std::string handle_line(std::string_view line, std::uint64_t now_ms);
    void disconnect();

private:
    const core::DeviceMetadata& metadata_;
    vault_runtime::Runtime& runtime_;
    registration::Store& registration_;
    time::TimeService& time_service_;
    StagedSessionV2Handler& session_handler_;
    CanonicalVmkSink& vmk_sink_;
};

std::string canonical_v2_message_too_large_response();

}  // namespace m5auth::provisioning
