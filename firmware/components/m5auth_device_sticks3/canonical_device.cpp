#include "m5auth/device/sticks3/canonical_device.hpp"
#include "m5auth/device/sticks3/label_scroll_state.hpp"
#include "m5auth/device/sticks3/totp_validity.hpp"
#include "m5auth/device/sticks3/ui_palette.hpp"

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
constexpr std::uint64_t kLabelScrollDelayMs = 2'000;
constexpr std::uint64_t kLabelScrollEndDelayMs = 2'000;
constexpr std::uint64_t kLabelScrollStepMs = 40;
constexpr int kLabelScrollStepPx = 1;
constexpr TickType_t kUiPollInterval = pdMS_TO_TICKS(20);
// Issue #139 Human Gate: the pre-#139 readable size is the minimum for every
// normal user-visible Device UI string. Do not introduce a compact size below it.
constexpr std::uint8_t kReadableTextSize = 2;
constexpr std::uint8_t kOtpTextSize = 4;
constexpr int kOtpDigitGapPx = 3;

constexpr std::uint16_t kColorBlack = 0x0000;
constexpr std::uint16_t kColorWhite = 0xffff;
constexpr std::uint16_t kColorGood = 0x07e0;
constexpr std::uint16_t kColorAttention = 0xffe0;
constexpr std::uint16_t kColorError = 0xf800;

constexpr int kHeaderY = 0;
constexpr int kPrimaryLineY = 20;
constexpr int kSecondaryLineY = 40;
constexpr int kTertiaryLineY = 60;
constexpr int kStatusBandHeight = 18;
constexpr int kAccountLabelY = 80;
constexpr int kAccountLabelHeight = 18;
constexpr int kOtpY = 101;
constexpr int kOtpBandHeight = 34;
constexpr int kHelpFirstY = 99;
constexpr int kHelpSecondY = 117;

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

std::uint16_t readiness_color(time::Readiness readiness) {
    switch (readiness) {
        case time::Readiness::kReady: return kColorGood;
        case time::Readiness::kNotSynced: return kColorAttention;
        case time::Readiness::kStale: return kColorError;
    }
    return kColorError;
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

std::uint16_t runtime_state_color(vault_runtime::State state) {
    switch (state) {
        case vault_runtime::State::kUnlocked: return kColorGood;
        case vault_runtime::State::kLocked:
        case vault_runtime::State::kUnprovisioned:
            return kColorAttention;
        case vault_runtime::State::kReprovisionRequired:
        case vault_runtime::State::kError:
            return kColorError;
    }
    return kColorError;
}

void prepare_readable_display() {
    M5.Display.setTextSize(kReadableTextSize);
    M5.Display.setTextColor(kColorWhite, kColorBlack);
    M5.Display.setTextWrap(false);
    M5.Display.setCursor(0, 0);
}

void draw_line(const char* text, int y) {
    M5.Display.setTextSize(kReadableTextSize);
    M5.Display.setTextColor(kColorWhite, kColorBlack);
    M5.Display.setCursor(0, y);
    M5.Display.print(text);
}

void draw_accent_line(const char* text, int y, std::uint16_t color) {
    M5.Display.setTextSize(kReadableTextSize);
    M5.Display.setTextColor(color, kColorBlack);
    M5.Display.setCursor(0, y);
    M5.Display.print(text);
    M5.Display.setTextColor(kColorWhite, kColorBlack);
}

void draw_semantic_line(
    const char* prefix,
    const char* value,
    std::uint16_t value_color,
    int y
) {
    M5.Display.setTextSize(kReadableTextSize);
    M5.Display.setTextColor(kColorWhite, kColorBlack);
    M5.Display.setCursor(0, y);
    M5.Display.print(prefix);
    const int value_x = M5.Display.textWidth(prefix);
    M5.Display.setTextColor(value_color, kColorBlack);
    M5.Display.setCursor(value_x, y);
    M5.Display.print(value);
    M5.Display.setTextColor(kColorWhite, kColorBlack);
}

M5Canvas* account_label_canvas() {
    static M5Canvas canvas;
    static bool initialized = false;
    static bool available = false;
    if (!initialized) {
        initialized = true;
        canvas.setColorDepth(8);
        available = canvas.createSprite(
            static_cast<std::int32_t>(M5.Display.width()),
            kAccountLabelHeight
        ) != nullptr;
        if (available) {
            canvas.setTextSize(kReadableTextSize);
            canvas.setTextColor(kColorWhite, kColorBlack);
            canvas.setTextWrap(false);
            canvas.clear(0x0000);
        }
    }
    return available ? &canvas : nullptr;
}

void draw_otp(std::uint32_t revealed_code) {
    char otp[7]{};
    std::snprintf(
        otp,
        sizeof(otp),
        "%06lu",
        static_cast<unsigned long>(revealed_code)
    );

    M5.Display.setTextSize(kOtpTextSize);
    M5.Display.setTextColor(kColorWhite, kColorBlack);
    const int digit_width = M5.Display.textWidth("0");
    const int group_gap = digit_width / 2;
    const int total_width =
        (digit_width * 6) + (kOtpDigitGapPx * 5) + group_gap;
    const int display_width = static_cast<int>(M5.Display.width());
    int x = std::max(0, (display_width - total_width) / 2);

    for (std::size_t index = 0; index < 6; ++index) {
        M5.Display.setCursor(x, kOtpY);
        M5.Display.print(otp[index]);
        x += digit_width;
        if (index < 5) {
            x += kOtpDigitGapPx;
        }
        if (index == 2) {
            x += group_gap;
        }
    }

    M5.Display.setTextSize(kReadableTextSize);
    vault_runtime::secure_zero(otp, sizeof(otp));
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

#if M5AUTH_TEST_SCREEN_SNAPSHOT
bool CanonicalUiController::screen_snapshot(ScreenSnapshot* output) const {
    if (output == nullptr) return false;
    std::lock_guard<std::mutex> view(view_mutex_);
    if (!rendered_snapshot_ready_) return false;
    *output = last_rendered_snapshot_;
    return true;
}
#endif

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

void CanonicalUiController::reset_label_scroll(std::uint64_t now_ms) {
    label_scroll::reset(now_ms, &label_scroll_epoch_ms_, &label_scroll_offset_px_);
}

bool CanonicalUiController::update_label_scroll(std::uint64_t now_ms) {
    if (storage_error_) return false;
    if (!vault_visible_ || credentials_.empty() || selected_index_ >= credentials_.size()) {
        return label_scroll::update_offset(false, 0, &label_scroll_offset_px_);
    }

    std::string label = display_label(credentials_[selected_index_]);
    M5.Display.setTextSize(kReadableTextSize);
    const int label_width = M5.Display.textWidth(label.c_str());
    wipe_text(&label);

    const int viewport_width = static_cast<int>(M5.Display.width());
    if (label_width <= viewport_width) {
        return label_scroll::update_offset(false, 0, &label_scroll_offset_px_);
    }

    const int max_offset = label_width - viewport_width;
    const int desired_offset = label_scroll::cycle_offset_px(
        storage_error_,
        label_scroll_epoch_ms_,
        now_ms,
        kLabelScrollDelayMs,
        kLabelScrollStepMs,
        kLabelScrollStepPx,
        max_offset,
        kLabelScrollEndDelayMs
    );
    return label_scroll::update_offset(
        storage_error_,
        desired_offset,
        &label_scroll_offset_px_
    );
}

void CanonicalUiController::hide_reveal() {
    revealed_code_ = 0;
    reveal_deadline_ms_ = 0;
    revealed_period_index_ = 0;
    validity_seconds_remaining_ = 0;
    reveal_active_ = false;
    reset_label_scroll(monotonic_ms());
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
    reset_label_scroll(monotonic_ms());
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
            const bool previous_storage_error = storage_error_;
            storage_error_ = false;
            (void)label_scroll::on_screen_hidden_changed(
                previous_storage_error,
                storage_error_,
                monotonic_ms(),
                &label_scroll_epoch_ms_,
                &label_scroll_offset_px_
            );
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
    reset_label_scroll(monotonic_ms());
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
    const bool previous_storage_error = storage_error_;
    storage_error_ = status != vault_runtime::Status::kOk;
    (void)label_scroll::on_screen_hidden_changed(
        previous_storage_error,
        storage_error_,
        monotonic_ms(),
        &label_scroll_epoch_ms_,
        &label_scroll_offset_px_
    );
    return status == vault_runtime::Status::kOk;
}

void CanonicalUiController::select_next() {
    if (credentials_.empty()) return;
    hide_reveal();
    selected_index_ = (selected_index_ + 1) % credentials_.size();
    reset_label_scroll(monotonic_ms());
    (void)persist_selection();
}

void CanonicalUiController::select_previous() {
    if (credentials_.empty()) return;
    hide_reveal();
    selected_index_ = selected_index_ == 0
        ? credentials_.size() - 1
        : selected_index_ - 1;
    reset_label_scroll(monotonic_ms());
    (void)persist_selection();
}

bool CanonicalUiController::refresh_revealed_totp() {
    if (!vault_visible_ || credentials_.empty() || selected_index_ >= credentials_.size()) {
        last_generate_result_ = totp::GenerateResult::kAccountNotFound;
        return false;
    }

    std::uint32_t code = 0;
    for (int attempt = 0; attempt < 2; ++attempt) {
        totp::GenerateMetadata generation{};
        {
            std::lock_guard<std::recursive_mutex> access(runtime_access_mutex_);
            last_generate_result_ = generator_.generate_for_credential(
                credentials_[selected_index_].credential_id,
                &code,
                &generation
            );
        }
        if (last_generate_result_ != totp::GenerateResult::kOk) break;

        std::uint64_t current_unix_seconds = 0;
        if (!time_service_.current_unix_seconds(&current_unix_seconds)) {
            last_generate_result_ = totp::GenerateResult::kTimeStale;
            break;
        }

        const auto generated_validity = totp_validity::from_unix_seconds(
            generation.unix_seconds
        );
        const auto current_validity = totp_validity::from_unix_seconds(
            current_unix_seconds
        );
        if (!totp_validity::same_period(generated_validity, current_validity)) {
            // The period rolled while generation was in progress. Wipe this code
            // and retry once so the visible OTP and countdown are one period.
            vault_runtime::secure_zero(&code, sizeof(code));
            continue;
        }

        revealed_code_ = code;
        revealed_period_index_ = current_validity.period_index;
        validity_seconds_remaining_ = current_validity.seconds_remaining;
        vault_runtime::secure_zero(&code, sizeof(code));
        return true;
    }

    vault_runtime::secure_zero(&code, sizeof(code));
    return false;
}

void CanonicalUiController::reveal_selected(std::uint64_t now_ms) {
    hide_reveal();
    last_generate_result_ = totp::GenerateResult::kOk;
    if (!refresh_revealed_totp()) return;

    reveal_active_ = true;
    reveal_deadline_ms_ = now_ms >
            std::numeric_limits<std::uint64_t>::max() - kOtpRevealDurationMs
        ? std::numeric_limits<std::uint64_t>::max()
        : now_ms + kOtpRevealDurationMs;
    reset_label_scroll(now_ms);
}

void CanonicalUiController::render_account_label() {
    if (storage_error_ || !vault_visible_ || credentials_.empty() ||
        selected_index_ >= credentials_.size()) {
        return;
    }

    std::string label = display_label(credentials_[selected_index_]);
    if (M5Canvas* canvas = account_label_canvas(); canvas != nullptr) {
        canvas->clear(0x0000);
        canvas->setTextSize(kReadableTextSize);
        canvas->setTextColor(kColorWhite, kColorBlack);
        canvas->setTextWrap(false);
        canvas->setCursor(-label_scroll_offset_px_, 0);
        canvas->print(label.c_str());
        canvas->pushSprite(&M5.Display, 0, kAccountLabelY);
        // The sprite is only a transient drawing surface. Clear its pixels after
        // the blit so it does not become another persistent credential-label copy.
        canvas->clear(0x0000);
    } else {
        // Allocation failure still avoids the Human-Gate defect: update only the
        // label band rather than clearing/redrawing the whole 240x135 display.
        M5.Display.fillRect(
            0,
            kAccountLabelY,
            static_cast<std::int32_t>(M5.Display.width()),
            kAccountLabelHeight,
            kColorBlack
        );
        M5.Display.setTextSize(kReadableTextSize);
        M5.Display.setTextColor(kColorWhite, kColorBlack);
        M5.Display.setTextWrap(false);
        M5.Display.setCursor(-label_scroll_offset_px_, kAccountLabelY);
        M5.Display.print(label.c_str());
    }
    wipe_text(&label);
}

void CanonicalUiController::render_reveal_validity() {
    M5.Display.fillRect(
        0,
        kTertiaryLineY,
        static_cast<std::int32_t>(M5.Display.width()),
        kStatusBandHeight,
        kColorBlack
    );
    M5.Display.setTextSize(kReadableTextSize);
    M5.Display.setTextColor(kColorWhite, kColorBlack);
    M5.Display.setCursor(0, kTertiaryLineY);
    M5.Display.printf(
        "Valid: %us",
        static_cast<unsigned>(validity_seconds_remaining_)
    );
}

void CanonicalUiController::render_reveal_region() {
    // A period rollover commits the new code and validity under view_mutex_.
    // Erase the old OTP first so the new-period validity can never be shown next
    // to old-period OTP pixels. The temporary blank OTP band is fail-safe and
    // bounded; no whole-screen clear/redraw is introduced.
    M5.Display.fillRect(
        0,
        kOtpY,
        static_cast<std::int32_t>(M5.Display.width()),
        kOtpBandHeight,
        kColorBlack
    );
    render_reveal_validity();
    draw_otp(revealed_code_);
}

void CanonicalUiController::render() {
    // render() is called only while view_mutex_ is held. Capture the live
    // externally synchronized inputs exactly once, use those same values for the
    // physical LCD draw, and publish the sanitized snapshot only after drawing.
    const time::Snapshot time_status = time_service_.status();
    const PresenceView presence = presence_.view();

#if M5AUTH_TEST_SCREEN_SNAPSHOT
    ScreenSnapshot rendered_snapshot{};
    rendered_snapshot.runtime_state = runtime_state_;
    rendered_snapshot.trusted_time_readiness = time_status.readiness;
    rendered_snapshot.presence = presence;
    if (presence.active) {
        rendered_snapshot.screen_mode = ScreenMode::kUnlockRequest;
    } else if (storage_error_) {
        rendered_snapshot.screen_mode = ScreenMode::kVaultUnavailable;
    } else if (!vault_visible_) {
        rendered_snapshot.screen_mode = ScreenMode::kOpenWeb;
    } else if (credentials_.empty()) {
        rendered_snapshot.screen_mode = ScreenMode::kNoAccounts;
    } else if (reveal_active_ && time_status.readiness == time::Readiness::kReady) {
        rendered_snapshot.screen_mode = ScreenMode::kOtpRevealed;
    } else {
        rendered_snapshot.screen_mode = ScreenMode::kAccountView;
    }
#endif

    M5.Display.clear();
    prepare_readable_display();
    draw_accent_line("M5Authenticator", kHeaderY, ui_palette::kProductTitle);

    if (presence.active) {
        draw_line("UNLOCK REQUEST", kPrimaryLineY);
        draw_line(session::presence_operation_text(presence.operation), kSecondaryLineY);
        int status_y = kTertiaryLineY;
        if (presence.operation == session::PresenceOperation::kFactoryReset) {
            draw_line("ERASE DEVICE DATA", status_y);
            status_y += 20;
        }
        if (presence.confirmed) {
            draw_line("Confirmed", status_y);
            draw_line("Waiting for browser", status_y + 20);
        } else {
            draw_accent_line(
                "Press A to confirm",
                status_y,
                ui_palette::kConfirmationAction
            );
            draw_line("Expires in 30 sec", status_y + 20);
        }
    } else {
        draw_semantic_line(
            "State: ",
            runtime_state_text(runtime_state_),
            runtime_state_color(runtime_state_),
            kPrimaryLineY
        );
        draw_semantic_line(
            "Time: ",
            readiness_text(time_status.readiness),
            readiness_color(time_status.readiness),
            kSecondaryLineY
        );

        if (storage_error_) {
            draw_line("Vault unavailable", kTertiaryLineY);
        } else if (!vault_visible_) {
            draw_line("Open Web app", kTertiaryLineY);
        } else if (credentials_.empty()) {
            draw_line("No accounts", kTertiaryLineY);
        } else {
            const bool generate_error =
                last_generate_result_ != totp::GenerateResult::kOk &&
                last_generate_result_ != totp::GenerateResult::kNotSynced &&
                last_generate_result_ != totp::GenerateResult::kTimeStale;
            if (reveal_active_ && time_status.readiness == time::Readiness::kReady) {
                render_reveal_validity();
            } else {
                M5.Display.setTextSize(kReadableTextSize);
                M5.Display.setTextColor(kColorWhite, kColorBlack);
                M5.Display.setCursor(0, kTertiaryLineY);
                if (generate_error) {
                    M5.Display.print("OTP unavailable");
                } else {
                    M5.Display.printf(
                        "%u / %u",
                        static_cast<unsigned>(selected_index_ + 1),
                        static_cast<unsigned>(credentials_.size())
                    );
                }
            }

            render_account_label();

            if (reveal_active_ && time_status.readiness == time::Readiness::kReady) {
                draw_otp(revealed_code_);
            } else {
                draw_line("click: 1x next", kHelpFirstY);
                draw_line("2x prev / hold OTP", kHelpSecondY);
            }
        }
    }

#if M5AUTH_TEST_SCREEN_SNAPSHOT
    // Commit only after all LCD writes above completed. view_mutex_ stays held by
    // the caller, so readers can observe only a previous or this completed render.
    last_rendered_snapshot_ = rendered_snapshot;
    rendered_snapshot_ready_ = true;
#endif
}

void CanonicalUiController::run() {
    time::Readiness previous_readiness = time_service_.status().readiness;
    PresenceView previous_presence = presence_.view();
    std::uint64_t last_refresh_ms = monotonic_ms();
    {
        std::lock_guard<std::mutex> view(view_mutex_);
        (void)refresh_credentials(true);
        reset_label_scroll(last_refresh_ms);
        render();
    }

    while (true) {
        bool dirty = false;
        bool presence_changed = false;
        M5.update();
        const std::uint64_t now_ms = monotonic_ms();

        dirty = presence_.expire(now_ms) || dirty;
        PresenceView current_presence = presence_.view();
        if (!same_presence(current_presence, previous_presence)) {
            previous_presence = current_presence;
            presence_changed = true;
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
            if (!same_presence(current_presence, previous_presence)) {
                presence_changed = true;
            }
            previous_presence = current_presence;
        }
        presence_gesture_quarantine_.observe(
            M5.BtnA.isPressed(),
            M5.BtnA.wasDecideClickCount(),
            now_ms
        );

        {
            std::lock_guard<std::mutex> view(view_mutex_);
            if (presence_changed) {
                reset_label_scroll(now_ms);
            }

            const time::Readiness readiness = time_service_.status().readiness;
            if (readiness != previous_readiness) {
                previous_readiness = readiness;
                reset_label_scroll(now_ms);
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
                reset_label_scroll(now_ms);
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

            bool validity_changed = false;
            bool rollover_changed = false;
            if (reveal_active_) {
                std::uint64_t current_unix_seconds = 0;
                if (!time_service_.current_unix_seconds(&current_unix_seconds)) {
                    last_generate_result_ = totp::GenerateResult::kTimeStale;
                    hide_reveal();
                    dirty = true;
                } else {
                    const auto current_validity = totp_validity::from_unix_seconds(
                        current_unix_seconds
                    );
                    if (current_validity.period_index != revealed_period_index_) {
                        // Refresh code + period metadata together. This path never
                        // writes reveal_deadline_ms_, so rollover cannot extend 10 s.
                        if (refresh_revealed_totp()) {
                            rollover_changed = true;
                        } else {
                            hide_reveal();
                            dirty = true;
                        }
                    } else if (
                        current_validity.seconds_remaining != validity_seconds_remaining_
                    ) {
                        validity_seconds_remaining_ = current_validity.seconds_remaining;
                        validity_changed = true;
                    }
                }
            }

            if (!current_presence.active && !presence_gesture_quarantine_.active()) {
                if (M5.BtnA.wasHold()) {
                    reveal_selected(now_ms);
                    dirty = true;
                } else if (M5.BtnA.wasDoubleClicked()) {
                    select_previous();
                    dirty = true;
                } else if (M5.BtnA.wasSingleClicked()) {
                    if (reveal_active_) {
                        hide_reveal();
                    } else {
                        select_next();
                    }
                    dirty = true;
                }
            }

            if (observed_state == vault_runtime::State::kUnlocked &&
                !current_presence.active &&
                now_ms - last_refresh_ms >= kCredentialRefreshIntervalMs) {
                dirty = refresh_credentials(false) || dirty;
                last_refresh_ms = now_ms;
            }

            bool label_scroll_changed = false;
            if (!current_presence.active && observed_state == vault_runtime::State::kUnlocked) {
                label_scroll_changed = update_label_scroll(now_ms);
            }

            if (dirty) {
                render();
            } else if (rollover_changed) {
                // Code and validity are committed under view_mutex_ and then both
                // bounded bands are redrawn as one rollover update.
                render_reveal_region();
            } else if (validity_changed) {
                render_reveal_validity();
            } else if (label_scroll_changed) {
                // Scroll-only ticks update the double-buffered label band. The
                // rest of the LCD remains untouched, eliminating whole-screen
                // clear/redraw flicker observed in the physical Human Gate.
                render_account_label();
            }
        }
        vTaskDelay(kUiPollInterval);
    }
}

}  // namespace m5auth::device::sticks3
