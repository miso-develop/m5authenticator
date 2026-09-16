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

#ifndef M5AUTH_TEST_SCREEN_SNAPSHOT
#define M5AUTH_TEST_SCREEN_SNAPSHOT 0
#endif

namespace m5auth::device::sticks3 {

inline constexpr char kDeviceModel[] = "M5StickS3";

void initialize();

struct PresenceView {
    bool active{false};
    bool confirmed{false};
    session::PresenceOperation operation{session::PresenceOperation::kTrustedBrowserUnlock};
};

#if M5AUTH_TEST_SCREEN_SNAPSHOT
enum class ScreenMode : std::uint8_t {
    kUnlockRequest,
    kVaultUnavailable,
    kOpenWeb,
    kNoAccounts,
    kOtpRevealed,
    kAccountView,
};

// Test-only diagnostics may copy this structure, but never the UI-private
// credential strings, OTP value, selection index, reveal deadline, or key data.
struct ScreenSnapshot {
    vault_runtime::State runtime_state{vault_runtime::State::kUnprovisioned};
    time::Readiness trusted_time_readiness{time::Readiness::kNotSynced};
    PresenceView presence{};
    ScreenMode screen_mode{ScreenMode::kOpenWeb};
};
#endif

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

    void observe_button_state(bool pressed) {
        std::lock_guard<std::mutex> lock(mutex_);
        gate_.observe_input_state(pressed);
    }
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

    // Called synchronously after a VMK-destruction boundary has changed the
    // Runtime state. It wipes decrypted account labels/IDs and OTP reveal state
    // and redraws before the security operation is allowed to return.
    void security_boundary_clear();

#if M5AUTH_TEST_SCREEN_SNAPSHOT
    // Copies the last sanitized state committed by a completed render(). Returns
    // false until the first LCD render has completed, so the default cache value
    // can never be reported as test evidence.
    bool screen_snapshot(ScreenSnapshot* output) const;
#endif

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
    void render_account_label();
    void render_reveal_validity();
    void render_reveal_region();
    void hide_reveal();
    void reveal_selected(std::uint64_t now_ms);
    bool refresh_revealed_totp();
    void reset_label_scroll(std::uint64_t now_ms);
    bool update_label_scroll(std::uint64_t now_ms);

    static void wipe_text(std::string* value);
    static std::string display_label(const CredentialView& credential);

    vault_runtime::Runtime& runtime_;
    totp::VaultGenerator& generator_;
    time::TimeService& time_service_;
    std::recursive_mutex& runtime_access_mutex_;
    CanonicalPresence& presence_;

    // UI-private decrypted state is accessed by the UI task and by synchronous
    // security-boundary invalidation from the protocol task.
    mutable std::mutex view_mutex_;
    std::vector<CredentialView> credentials_;
    std::size_t selected_index_{0};
    std::uint64_t visible_generation_{0};
    vault_runtime::State runtime_state_{vault_runtime::State::kUnprovisioned};
    bool vault_visible_{false};
    bool storage_error_{false};
    bool reveal_active_{false};
    std::uint32_t revealed_code_{0};
    std::uint64_t reveal_deadline_ms_{0};
    // Non-secret RFC6238 display metadata. The deadline above is deliberately
    // independent: rollover updates these fields without extending the 10 s reveal.
    std::uint64_t revealed_period_index_{0};
    std::uint8_t validity_seconds_remaining_{0};
    totp::GenerateResult last_generate_result_{totp::GenerateResult::kOk};
    // Scrolling stores only timing and pixel offset. The decrypted credential
    // label stays in the existing UI-private credential cache and is never copied
    // into a separate persistent/loggable scroll buffer.
    std::uint64_t label_scroll_epoch_ms_{0};
    int label_scroll_offset_px_{0};
    session::PresenceGestureQuarantine presence_gesture_quarantine_;
#if M5AUTH_TEST_SCREEN_SNAPSHOT
    ScreenSnapshot last_rendered_snapshot_{};
    bool rendered_snapshot_ready_{false};
#endif
    TaskHandle_t task_{nullptr};
};

}  // namespace m5auth::device::sticks3
