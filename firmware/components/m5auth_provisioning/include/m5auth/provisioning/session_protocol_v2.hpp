#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

#include "m5auth/session/protocol_v2.hpp"

namespace m5auth::provisioning {

inline constexpr std::size_t kMaxSessionV2MessageBytes = 2048;

struct SessionV2DeviceSnapshot {
    std::string device_id;
    bool vault_present{false};
    session::protocol_v2::VaultId vault_id{};
    std::uint64_t generation{0};
    bool registration_present{false};
    session::protocol_v2::RegistrationId registration_id{};
    std::uint32_t registration_epoch{0};
    session::protocol_v2::BrkPublicKey brk_public_key{};
};

bool session_v2_begin_matches_snapshot(
    const session::protocol_v2::BeginContext& context,
    const SessionV2DeviceSnapshot& snapshot
);

// Device-owned source of non-secret state used to authenticate what the Web
// claims in session.begin. The handler must never use a Web-supplied current
// BRK as the verification root without matching it to this snapshot first.
class SessionV2BindingSource {
public:
    virtual ~SessionV2BindingSource() = default;
    virtual bool snapshot(SessionV2DeviceSnapshot* output) const = 0;
};

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
        const SessionV2BindingSource& binding_source,
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
    bool current_binding_matches() const;
    std::string fail_closed(int id, const char* code);
    void clear_context();

    session::protocol_v2::AttemptCoordinator& coordinator_;
    const SessionV2BindingSource& binding_source_;
    SessionV2VmkSink& vmk_sink_;
    session::protocol_v2::BeginContext context_{};
    bool context_active_{false};
};

std::string session_v2_message_too_large_response();

}  // namespace m5auth::provisioning
