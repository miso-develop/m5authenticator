#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

#include "m5auth/session/protocol_v2.hpp"

namespace m5auth::provisioning {

inline constexpr std::size_t kMaxSessionV2MessageBytes = 2048;

// Task #54 boundary between the staged wire/session handler and the canonical
// Vault runtime. Task #55 supplies the production implementation and owns all
// registration/generation/state mutation after an authenticated VMK arrives.
class SessionV2VmkSink {
public:
    virtual ~SessionV2VmkSink() = default;
    virtual bool install_vmk(
        const session::protocol_v2::BeginContext& context,
        const session::Vmk& vmk
    ) = 0;
};

class StagedSessionV2Handler final {
public:
    StagedSessionV2Handler(
        session::protocol_v2::AttemptCoordinator& coordinator,
        SessionV2VmkSink& vmk_sink
    );
    ~StagedSessionV2Handler();

    StagedSessionV2Handler(const StagedSessionV2Handler&) = delete;
    StagedSessionV2Handler& operator=(const StagedSessionV2Handler&) = delete;

    // Parses one bounded NDJSON line without its trailing newline. This class is
    // intentionally not mounted into the canonical Protocol 1 Session yet.
    std::string handle_line(std::string_view line, std::uint64_t now_ms);

    void disconnect();

private:
    void clear_context();

    session::protocol_v2::AttemptCoordinator& coordinator_;
    SessionV2VmkSink& vmk_sink_;
    session::protocol_v2::BeginContext context_{};
    bool context_active_{false};
};

std::string session_v2_message_too_large_response();

}  // namespace m5auth::provisioning
