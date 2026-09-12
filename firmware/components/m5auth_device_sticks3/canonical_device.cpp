#include "m5auth/device/sticks3/canonical_device.hpp"

#include <algorithm>
#include <cstdio>
#include <limits>
#include <optional>
#include <utility>

#include "M5Unified.h"
#include "esp_timer.h"

namespace m5auth::device::sticks3 {
namespace {

constexpr std::uint64_t kCredentialRefreshIntervalMs = 1'000;
constexpr std::uint64_t kOtpRevealDurationMs = 10'000;
constexpr TickType_t kUiPollInterval = pdMS_TO_TICKS(20);
constexpr std::uint8_t kReadableTextSize = 2;
constexpr std::uint8_t kOtpTextSize = 4;

std::uint64_t monotonic_ms() {
    const std::int64_t microseconds = esp_timer_get_time();
    return microseconds <= 0
        ? 0
        : static_cast<std::uint64_t>(microseconds / 1'000);
}

const char* readiness_text(time::Readiness readiness) {
    switch (readiness) {
        case time::Readiness::kNotSynced: return "NOT SYNCED";
        case time::Readiness::kReady: return "READY";
        case time::Readiness::kStale: return "TIME STALE";
    }
    return "TIME ERROR";
}

const char* runtime_state_text(vault_runtime::State state) {
    switch (state) {
        case vault_runtime::State::kUnprovisioned: return "UNPROVISIONED";
        case vault_runtime::State::kReprovisionRequired: return "REPROVISION";
        case vault_runtime::State::kLocked: return "LOCKED";
        case vault_runtime::State::kUnlocked: return "UNLOCKED";
        case vault_runtime::State::kError: return "SECURITY ERROR";
    }
    return "SECURITY ERROR";
}

void prepare_readable_display() {
    M5.Display.setTextSize(kReadableTextSize);
    M5.Display.setTextColor(0xffff, 0x0000);
    M5.Display.setTextWrap(false);
    M5.Display.setCursor(0, 0);
}

bool same_presence(const PresenceView& left, const PresenceView& right) {
    return left.active == right.active &&
        left.confirmed == right.confirmed &&
        left.operation == right.operation;
}

}  // namespace

bool CanonicalPresence::begin_presence(
    session::PresenceOperation operation,
    const session::AttemptId& attempt_id,
    std::uint64_t now_ms
) {
    std::lock_guard<std::mutex> lock(mutex_);
    return gate_.begin(operation, attempt_id, now_ms, button_press_generation_);
}

bool CanonicalPresence::consume_presence(
    const session::AttemptId& attempt_id,
    std::uint64_t now_ms
) {
    std::lock_guard<std::mutex> lock(mutex_);
    return gate_.consume_confirmation(attempt_id, now_ms);
}

void CanonicalPresence::cancel_presence() {
    std::lock_guard<std::mutex> lock(mutex_);
    gate_.cancel();
}

bool CanonicalPresence::presence_confirmed() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return gate_.state() == session::PresenceState::kConfirmed;
}

bool CanonicalPresence::button_pressed(std::uint64_t now_ms) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (button_press_generation_ != std::numeric_limits<std::uint64_t>::max()) {
        ++button_press_generation_;
    }
    if (!gate_.active()) return false;
    return gate_.confirm_current(now_ms, button_press_generation_);
}

bool CanonicalPresence::expire(std::uint64_t now_ms) {
    std::lock_guard<std::mutex> lock(mutex_);
    return gate_.expire(now_ms);
}

PresenceView CanonicalPresence::view() const {
    std::lock_guard<std::mutex> lock(mutex_);
    PresenceView result;
    result.active = gate_.active();
    result.confirmed = gate_.state() == session::PresenceState::kConfirmed;
    result.operation = gate_.operation();
    return result;
}

CanonicalUiController::CanonicalUiController(
    vault_runtime::Runtime& runtime,
    totp::VaultGenerator& generator,
    time::TimeService& time_service,
    std::recursive_mutex& runtime_access_mutex,
    CanonicalPresence& presence
) : runtime_(runtime),
    generator_(generator),
    time_service_(time_service),
    runtime_access_mutex_(runtime_access_mutex),
    presence_(presence) {}

bool CanonicalUiController::start() {
    if (task_ != nullptr) return true;
    return xTaskCreate(
        &CanonicalUiController::task_entry,
        "m5auth_ui_v2",
        8'192,
        this,
        5,
        &task_
    ) == pdPASS;
}

void CanonicalUiController::security_boundary_clear() {
    std::lock_guard<std::mutex> view(view_mutex_);
    vault_runtime::Metadata metadata{};
    {
        std::lock_guard<std::recursive_mutex> access(runtime_access_mutex_);
        const vault_runtime::Status status = runtime_.metadata(&metadata);
        if (status == vault_runtime::Status::kOk) {
            runtime_state_ = metadata.state;
            storage_error_ = metadata.state == vault_runtime::State::kError;
        } else {
            runtime_state_ = vault_runtime::State::kError;
            storage_error_ = true;
        }
    }
    (void)clear_private_view();
    last_generate_result_ = totp::GenerateResult::kOk;
    render();
}

void CanonicalUiController::task_entry(void* context) {
    auto* controller = static_cast<CanonicalUiController*>(context);
    controller->run();
    controller->task_ = nullptr;
    vTaskDelete(nullptr);
}

void CanonicalUiController::wipe_text(std::string* value) {
    if (value == nullptr) return;
    if (!value->empty()) vault_runtime::secure_zero(value->data(), value->size());
    value->clear();
}

std::string CanonicalUiController::display_label(const CredentialView& credential) {
    if (!credential.display_name.empty()) return credential.display_name;
    if (!credential.issuer.empty() && !credential.account.empty()) {
        return credential.issuer + ": " + credential.account;
    }
    if (!credential.issuer.empty()) return credential.issuer;
    if (!credential.account.empty()) return credential.account;
    return "Unnamed account";
}

void CanonicalUiController::hide_reveal() {
    revealed_code_ = 0;
    reveal_deadline_ms_ = 0;
    reveal_active_ = false;
}

bool CanonicalUiController::clear_private_view() {
    const bool changed = vault_visible_ || !credentials_.empty() || reveal_active_;
    hide_reveal();
    for (auto& credential : credentials_) {
        credential.credential_id.fill(0);
        wipe_text(&credential.issuer);
        wipe_text(&credential.account);
        wipe_text(&credential.display_name);
    }
    credentials_.clear();
    selected_index_ = 0;
    visible_generation_ = 0;
    vault_visible_ = false;
    return changed;
}

bool CanonicalUiController::refresh_credentials(bool force) {
    std::lock_guard<std::recursive_mutex> access(runtime_access_mutex_);

    vault_runtime::Metadata runtime_metadata;
    const vault_runtime::Status metadata_status = runtime_.metadata(&runtime_metadata);
    if (metadata_status != vault_runtime::Status::kOk) {
        const bool changed = clear_private_view() || !storage_error_;
        storage_error_ = true;
        runtime_state_ = vault_runtime::State::kError;
        return changed;
    }
    runtime_state_ = runtime_metadata.state;

    if (runtime_metadata.state != vault_runtime::State::kUnlocked) {
        const bool changed = clear_private_view() || storage_error_;
        storage_error_ = false;
        return changed;
    }
    if (!force && vault_visible_ && visible_generation_ == runtime_metadata.generation) {
        if (storage_error_) {
            storage_error_ = false;
            return true;
        }
        return false;
    }

    std::optional<vault_runtime::CredentialId> preferred;
    if (vault_visible_ && selected_index_ < credentials_.size()) {
        preferred = credentials_[selected_index_].credential_id;
    } else if (runtime_metadata.last_used.has_value()) {
        preferred = runtime_metadata.last_used;
    }

    std::vector<vault_runtime::CredentialMetadata> metadata;
    const vault_runtime::Status list_status = runtime_.list_credentials(&metadata);
    if (list_status != vault_runtime::Status::kOk) {
        const bool changed = clear_private_view() || !storage_error_;
        storage_error_ = true;
        return changed;
    }

    std::vector<CredentialView> next;
    next.reserve(metadata.size());
    for (auto& item : metadata) {
        CredentialView view;
        view.credential_id = item.credential_id;
        view.issuer = std::move(item.issuer);
        view.account = std::move(item.account);
        view.display_name = std::move(item.display_name);
        next.push_back(std::move(view));
    }

    std::size_t next_index = 0;
    if (preferred.has_value()) {
        const auto found = std::find_if(
            next.begin(),
            next.end(),
            [&](const CredentialView& credential) {
                return credential.credential_id == *preferred;
            }
        );
        if (found != next.end()) {
            next_index = static_cast<std::size_t>(std::distance(next.begin(), found));
        }
    }

    (void)clear_private_view();
    credentials_ = std::move(next);
    selected_index_ = credentials_.empty() ? 0 : next_index;
    visible_generation_ = runtime_metadata.generation;
    vault_visible_ = true;
    storage_error_ = false;
    return true;
}

bool CanonicalUiController::persist_selection() {
    if (!vault_visible_ || credentials_.empty() || selected_index_ >= credentials_.size()) {
        return true;
    }
    std::lock_guard<std::recursive_mutex> access(runtime_access_mutex_);
    const vault_runtime::Status status = runtime_.set_last_used(
        credentials_[selected_index_].credential_id
    );
    storage_error_ = status != vault_runtime::Status::kOk;
    return status == vault_runtime::Status::kOk;
}

void CanonicalUiController::select_next() {
    if (credentials_.empty()) return;
    hide_reveal();
    selected_index_ = (selected_index_ + 1) % credentials_.size();
    (void)persist_selection();
}

void CanonicalUiController::select_previous() {
    if (credentials_.empty()) return;
    hide_reveal();
    selected_index_ = selected_index_ == 0
        ? credentials_.size() - 1
        : selected_index_ - 1;
    (void)persist_selection();
}

void CanonicalUiController::reveal_selected(std::uint64_t now_ms) {
    hide_reveal();
    last_generate_result_ = totp::GenerateResult::kOk;
    if (!vault_visible_ || credentials_.empty() || selected_index_ >= credentials_.size()) return;

    std::uint32_t code = 0;
    {
        std::lock_guard<std::recursive_mutex> access(runtime_access_mutex_);
        last_generate_result_ = generator_.generate_for_credential(
            credentials_[selected_index_].credential_id,
            &code
        );
    }
    if (last_generate_result_ == totp::GenerateResult::kOk) {
        revealed_code_ = code;
        reveal_active_ = true;
        reveal_deadline_ms_ = now_ms >
                std::numeric_limits<std::uint64_t>::max() - kOtpRevealDurationMs
            ? std::numeric_limits<std::uint64_t>::max()
            : now_ms + kOtpRevealDurationMs;
    }
    vault_runtime::secure_zero(&code, sizeof(code));
}

void CanonicalUiController::render() {
    const time::Snapshot time_status = time_service_.status();
    const PresenceView presence = presence_.view();

    M5.Display.clear();
    prepare_readable_display();
    M5.Display.println("M5 Authenticator");

    if (presence.active) {
        M5.Display.println("UNLOCK REQUEST");
        M5.Display.println(session::presence_operation_text(presence.operation));
        if (presence.operation == session::PresenceOperation::kFactoryReset) {
            M5.Display.println("ERASE DEVICE DATA");
        }
        if (presence.confirmed) {
            M5.Display.println("Confirmed");
            M5.Display.println("Waiting for browser");
        } else {
            M5.Display.println("Press A to confirm");
            M5.Display.println("Expires in 30 sec");
        }
        return;
    }

    M5.Display.printf("State: %s\n", runtime_state_text(runtime_state_));
    M5.Display.printf("Time: %s\n", readiness_text(time_status.readiness));

    if (storage_error_) {
        M5.Display.println("Vault unavailable");
        return;
    }
    if (!vault_visible_) {
        M5.Display.println("Open Web app");
        return;
    }
    if (credentials_.empty()) {
        M5.Display.println("No accounts");
        return;
    }

    const CredentialView& selected = credentials_[selected_index_];
    std::string label = display_label(selected);
    M5.Display.printf(
        "%u / %u\n",
        static_cast<unsigned>(selected_index_ + 1),
        static_cast<unsigned>(credentials_.size())
    );
    M5.Display.println(label.c_str());
    wipe_text(&label);

    if (reveal_active_ && time_status.readiness == time::Readiness::kReady) {
        char otp[7]{};
        std::snprintf(
            otp,
            sizeof(otp),
            "%06lu",
            static_cast<unsigned long>(revealed_code_)
        );
        M5.Display.setTextSize(kOtpTextSize);
        M5.Display.println(otp);
        M5.Display.setTextSize(kReadableTextSize);
        vault_runtime::secure_zero(otp, sizeof(otp));
        return;
    }

    if (last_generate_result_ != totp::GenerateResult::kOk &&
        last_generate_result_ != totp::GenerateResult::kNotSynced &&
        last_generate_result_ != totp::GenerateResult::kTimeStale) {
        M5.Display.println("OTP unavailable");
    }
    M5.Display.println("Click: next");
    M5.Display.println("2x: previous");
    M5.Display.println("Hold: reveal OTP");
}

void CanonicalUiController::run() {
    time::Readiness previous_readiness = time_service_.status().readiness;
    PresenceView previous_presence = presence_.view();
    std::uint64_t last_refresh_ms = monotonic_ms();
    {
        std::lock_guard<std::mutex> view(view_mutex_);
        (void)refresh_credentials(true);
        render();
    }

    while (true) {
        bool dirty = false;
        M5.update();
        const std::uint64_t now_ms = monotonic_ms();

        dirty = presence_.expire(now_ms) || dirty;
        PresenceView current_presence = presence_.view();
        if (!same_presence(current_presence, previous_presence)) {
            previous_presence = current_presence;
            dirty = true;
        }

        if (current_presence.active) {
            presence_.observe_button_state(M5.BtnA.isPressed());
        }
        if (current_presence.active && M5.BtnA.wasPressed()) {
            const bool confirmed = presence_.button_pressed(now_ms);
            dirty = confirmed || dirty;
            if (confirmed) {
                presence_gesture_quarantine_.begin(now_ms, M5.BtnA.getHoldThresh());
            }
            current_presence = presence_.view();
            previous_presence = current_presence;
        }
        presence_gesture_quarantine_.observe(
            M5.BtnA.isPressed(),
            M5.BtnA.wasDecideClickCount(),
            now_ms
        );

        {
            std::lock_guard<std::mutex> view(view_mutex_);
            const time::Readiness readiness = time_service_.status().readiness;
            if (readiness != previous_readiness) {
                previous_readiness = readiness;
                dirty = true;
            }

            vault_runtime::State observed_state = vault_runtime::State::kError;
            {
                std::lock_guard<std::recursive_mutex> access(runtime_access_mutex_);
                vault_runtime::Metadata metadata;
                if (runtime_.metadata(&metadata) == vault_runtime::Status::kOk) {
                    observed_state = metadata.state;
                }
            }
            if (observed_state != runtime_state_) {
                runtime_state_ = observed_state;
                dirty = true;
            }
            if (observed_state != vault_runtime::State::kUnlocked && vault_visible_) {
                dirty = clear_private_view() || dirty;
            }

            if (reveal_active_ &&
                (readiness != time::Readiness::kReady || now_ms >= reveal_deadline_ms_ ||
                 observed_state != vault_runtime::State::kUnlocked)) {
                hide_reveal();
                dirty = true;
            }

            if (!current_presence.active && !presence_gesture_quarantine_.active()) {
                if (M5.BtnA.wasHold()) {
                    reveal_selected(now_ms);
                    dirty = true;
                } else if (M5.BtnA.wasDoubleClicked()) {
                    select_previous();
                    dirty = true;
                } else if (M5.BtnA.wasSingleClicked()) {
                    select_next();
                    dirty = true;
                }
            }

            if (observed_state == vault_runtime::State::kUnlocked &&
                !current_presence.active &&
                now_ms - last_refresh_ms >= kCredentialRefreshIntervalMs) {
                dirty = refresh_credentials(false) || dirty;
                last_refresh_ms = now_ms;
            }

            if (dirty) render();
        }
        vTaskDelay(kUiPollInterval);
    }
}

}  // namespace m5auth::device::sticks3
