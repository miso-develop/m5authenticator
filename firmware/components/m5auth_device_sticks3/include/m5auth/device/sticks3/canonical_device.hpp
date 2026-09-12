#pragma once

#include <cstddef>
#include <cstdint>
#include <mutex>
#include <string>
#include <vector>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "m5auth/session/protocol_v2.hpp"
#include "m5auth/time/time_service.hpp"
#include "m5auth/totp/generator.hpp"
#include "m5auth/vault_runtime/runtime.hpp"

namespace m5auth::device::sticks3 {

struct PresenceView {
    bool active{false};
    bool confirmed{false};
    session::PresenceOperation operation{session::PresenceOperation::kTrustedBrowserUnlock};
};

class CanonicalPresence final : public session::protocol_v2::PresenceBinding {
public:
    bool begin_presence(
        session::PresenceOperation operation,
        const session::AttemptId& attempt_id,
        std::uint64_t now_ms
    ) override;
    bool consume_presence(
        const session::AttemptId& attempt_id,
        std::uint64_t now_ms
    ) override;
    void cancel_presence() override;
    bool presence_confirmed() const override;

    void observe_button_state(bool pressed);
    bool button_pressed(std::uint64_t now_ms);
    bool expire(std::uint64_t now_ms);
    PresenceView view() const;

private:
    mutable std::mutex mutex_;
    std::uint64_t button_press_generation_{0};
    session::UserPresenceGate gate_;
};

class CanonicalUiController final {
public:
    CanonicalUiController(
        vault_runtime::Runtime& runtime,
        totp::VaultGenerator& generator,
        time::TimeService& time_service,
        std::recursive_mutex& runtime_access_mutex,
        CanonicalPresence& presence
    );

    CanonicalUiController(const CanonicalUiController&) = delete;
    CanonicalUiController& operator=(const CanonicalUiController&) = delete;

    bool start();

private:
    struct CredentialView {
        vault_runtime::CredentialId credential_id{};
        std::string issuer;
        std::string account;
        std::string display_name;
    };

    static void task_entry(void* context);
    void run();
    bool refresh_credentials(bool force = false);
    bool clear_private_view();
    bool persist_selection();
    void select_next();
    void select_previous();
    void render();
    void hide_reveal();
    void reveal_selected(std::uint64_t now_ms);

    static void wipe_text(std::string* value);
    static std::string display_label(const CredentialView& credential);

    vault_runtime::Runtime& runtime_;
    totp::VaultGenerator& generator_;
    time::TimeService& time_service_;
    std::recursive_mutex& runtime_access_mutex_;
    CanonicalPresence& presence_;

    std::vector<CredentialView> credentials_;
    std::size_t selected_index_{0};
    std::uint64_t visible_generation_{0};
    vault_runtime::State runtime_state_{vault_runtime::State::kUnprovisioned};
    bool vault_visible_{false};
    bool storage_error_{false};
    bool reveal_active_{false};
    std::uint32_t revealed_code_{0};
    std::uint64_t reveal_deadline_ms_{0};
    totp::GenerateResult last_generate_result_{totp::GenerateResult::kOk};
    session::PresenceGestureQuarantine presence_gesture_quarantine_;
    TaskHandle_t task_{nullptr};
};

}  // namespace m5auth::device::sticks3
