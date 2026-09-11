#pragma once

#include <cstdint>
#include <mutex>

#include "m5auth/provisioning/session_protocol_v2.hpp"
#include "m5auth/registration/registration.hpp"
#include "m5auth/vault_runtime/runtime.hpp"

namespace m5auth::provisioning {

inline constexpr std::uint64_t kPendingVaultVmkTtlMs = 30'000;

class CanonicalBindingSource final : public SessionV2BindingSource {
public:
    CanonicalBindingSource(
        const vault_runtime::Runtime& runtime,
        const registration::Store& registration,
        std::recursive_mutex& runtime_access_mutex
    ) : runtime_(runtime),
        registration_(registration),
        runtime_access_mutex_(runtime_access_mutex) {}

    bool snapshot(SessionV2DeviceSnapshot* output) const override;

private:
    const vault_runtime::Runtime& runtime_;
    const registration::Store& registration_;
    std::recursive_mutex& runtime_access_mutex_;
};

// Owns the production transition from authenticated Protocol v2 VMK delivery to
// the RAM-only Vault runtime. Initial provisioning and VMK re-key retain a VMK
// only as a short-lived pending value until the corresponding encrypted Vault
// envelope is supplied; every other path either installs it immediately into
// Runtime RAM or wipes it before returning.
class CanonicalVmkSink final : public SessionV2VmkSink {
public:
    CanonicalVmkSink(
        vault_runtime::Runtime& runtime,
        registration::Store& registration,
        std::recursive_mutex& runtime_access_mutex
    );
    ~CanonicalVmkSink() override;

    CanonicalVmkSink(const CanonicalVmkSink&) = delete;
    CanonicalVmkSink& operator=(const CanonicalVmkSink&) = delete;

    // Called by the canonical router before delegating session.begin. Recovery,
    // registration replacement, and VMK re-key destroy any resident VMK at this
    // boundary and never restore the previous unlocked state after cancellation.
    bool prepare_attempt(const session::protocol_v2::BeginContext& context);

    bool install_vmk(
        const session::protocol_v2::BeginContext& context,
        const session::Vmk& vmk
    ) override;

    void arm_pending_deadline(std::uint64_t now_ms);
    bool expire_pending(std::uint64_t now_ms);
    void cancel_pending();

    bool install_initial_vault(
        vault::VaultEnvelope envelope,
        std::uint64_t now_ms
    );
    bool install_rekeyed_vault(
        std::uint64_t expected_generation,
        vault::VaultEnvelope envelope,
        std::uint64_t now_ms
    );

    bool has_pending_vmk() const;
    session::protocol_v2::Operation pending_operation() const;

private:
    bool pending_valid(
        session::protocol_v2::Operation operation,
        std::uint64_t now_ms
    );

    vault_runtime::Runtime& runtime_;
    registration::Store& registration_;
    std::recursive_mutex& runtime_access_mutex_;
    session::Vmk pending_vmk_{};
    session::protocol_v2::BeginContext pending_context_{};
    bool pending_{false};
    bool deadline_armed_{false};
    std::uint64_t pending_expires_at_ms_{0};
};

}  // namespace m5auth::provisioning
