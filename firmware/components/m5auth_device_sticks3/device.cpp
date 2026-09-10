#include "m5auth/device/sticks3/device.hpp"

#include <cstdio>
#include <string>
#include <utility>
#include <vector>

#include "M5Unified.h"
#include "esp_timer.h"

namespace m5auth::device::sticks3 {
namespace {

constexpr std::uint64_t kAccountRefreshIntervalMs = 1'000;
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
        case time::Readiness::kNotSynced:
            return "NOT SYNCED";
        case time::Readiness::kReady:
            return "READY";
        case time::Readiness::kStale:
            return "TIME STALE";
    }
    return "TIME ERROR";
}

void prepare_readable_display() {
    M5.Display.setTextSize(kReadableTextSize);
    M5.Display.setTextColor(0xffff, 0x0000);
    M5.Display.setTextWrap(false);
    M5.Display.setCursor(0, 0);
}

}  // namespace

void initialize() {
    auto config = M5.config();

    // M5Authenticator has no audio feature. Leaving the StickS3 audio path
    // enabled needlessly powers the ES8311/AW8737 speaker chain and can make
    // some units emit audible high-frequency noise, especially on USB power.
    config.internal_spk = false;
    config.internal_mic = false;
    M5.begin(config);

    // Keep the speaker amplifier fail-silent even if a library/default change
    // initializes audio despite the configuration above.
    M5.Speaker.end();

    M5.Display.setRotation(1);
    M5.Display.clear();
    prepare_readable_display();
    M5.Display.println("M5 Authenticator");
    M5.Display.println("Starting...");
}

UiController::UiController(
    storage::Store& store,
    totp::Generator& generator,
    time::TimeService& time_service,
    std::mutex& storage_access_mutex
) : store_(store),
    generator_(generator),
    time_service_(time_service),
    storage_access_mutex_(storage_access_mutex) {}

bool UiController::start() {
    if (task_ != nullptr) return true;
    return xTaskCreate(
        &UiController::task_entry,
        "m5auth_ui",
        8'192,
        this,
        5,
        &task_
    ) == pdPASS;
}

void UiController::task_entry(void* context) {
    auto* controller = static_cast<UiController*>(context);
    controller->run();
    controller->task_ = nullptr;
    vTaskDelete(nullptr);
}

bool UiController::refresh_accounts() {
    std::vector<storage::AccountMetadata> accounts;
    std::uint32_t last_used = 0;

    std::lock_guard<std::mutex> lock(storage_access_mutex_);
    const storage::Status list_status = store_.list_accounts(&accounts);
    if (list_status != storage::Status::kOk) {
        const bool changed = !storage_error_;
        storage_error_ = true;
        return changed;
    }

    const storage::Status selection_status = store_.get_last_used(&last_used);
    if (selection_status != storage::Status::kOk) {
        const bool changed = !storage_error_;
        storage_error_ = true;
        return changed;
    }

    const bool recovered = storage_error_;
    bool changed = model_.update_accounts(std::move(accounts), last_used) || recovered;
    if (changed) last_generate_result_ = totp::GenerateResult::kOk;
    storage_error_ = false;

    const std::uint32_t selected = model_.selected_id();
    if (selected != 0 && selected != last_used) {
        const storage::Status set_status = store_.set_last_used(selected);
        if (set_status != storage::Status::kOk) {
            storage_error_ = true;
            changed = true;
        }
    }
    return changed;
}

bool UiController::persist_selection() {
    const std::uint32_t selected = model_.selected_id();
    if (selected == 0) return true;

    std::lock_guard<std::mutex> lock(storage_access_mutex_);
    const storage::Status status = store_.set_last_used(selected);
    storage_error_ = status != storage::Status::kOk;
    return status == storage::Status::kOk;
}

void UiController::render() {
    const time::Snapshot time_status = time_service_.status();

    M5.Display.clear();
    prepare_readable_display();
    M5.Display.println("M5 Authenticator");
    M5.Display.printf("Time: %s\n", readiness_text(time_status.readiness));

    if (storage_error_) {
        M5.Display.println("Storage unavailable");
        return;
    }

    const storage::AccountMetadata* selected = model_.selected_account();
    if (selected == nullptr) {
        M5.Display.println("No accounts");
        M5.Display.println("Open Web setup");
        return;
    }

    const std::string label = account_display_label(*selected);
    M5.Display.printf(
        "%u / %u\n",
        static_cast<unsigned>(model_.selected_position()),
        static_cast<unsigned>(model_.account_count())
    );
    M5.Display.println(label.c_str());

    if (model_.reveal_active() && time_status.readiness == time::Readiness::kReady) {
        char otp[7]{};
        std::snprintf(
            otp,
            sizeof(otp),
            "%06lu",
            static_cast<unsigned long>(model_.revealed_code())
        );
        M5.Display.setTextSize(kOtpTextSize);
        M5.Display.println(otp);
        M5.Display.setTextSize(kReadableTextSize);
        storage::secure_zero(otp, sizeof(otp));
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

void UiController::run() {
    (void)refresh_accounts();
    time::Readiness previous_readiness = time_service_.status().readiness;
    std::uint64_t last_refresh_ms = monotonic_ms();
    render();

    while (true) {
        bool dirty = false;
        M5.update();
        std::uint64_t now_ms = monotonic_ms();
        const time::Readiness readiness = time_service_.status().readiness;

        if (readiness != previous_readiness) {
            previous_readiness = readiness;
            dirty = true;
        }

        if (model_.reveal_active()) {
            if (readiness != time::Readiness::kReady) {
                dirty = model_.hide_reveal() || dirty;
            } else {
                dirty = model_.expire(now_ms) || dirty;
            }
        }

        // If a visible OTP just became invalid/expired, clear the physical display
        // before any following action can block on storage/provisioning work.
        if (dirty && !model_.reveal_active()) {
            render();
            dirty = false;
        }

        if (M5.BtnA.wasHold()) {
            if (model_.hide_reveal()) {
                render();
            }
            last_generate_result_ = totp::GenerateResult::kOk;
            const storage::AccountMetadata* selected = model_.selected_account();
            if (selected != nullptr) {
                std::uint32_t code = 0;
                {
                    std::lock_guard<std::mutex> lock(storage_access_mutex_);
                    last_generate_result_ = generator_.generate_for_account(
                        selected->id,
                        &code
                    );
                }
                now_ms = monotonic_ms();
                if (last_generate_result_ == totp::GenerateResult::kOk) {
                    (void)model_.reveal(code, now_ms);
                }
                storage::secure_zero(&code, sizeof(code));
            }
            dirty = true;
        } else if (M5.BtnA.wasDoubleClicked()) {
            last_generate_result_ = totp::GenerateResult::kOk;
            const bool was_revealing = model_.reveal_active();
            if (model_.select_previous()) {
                if (was_revealing) render();
                (void)persist_selection();
                dirty = true;
            }
        } else if (M5.BtnA.wasSingleClicked()) {
            last_generate_result_ = totp::GenerateResult::kOk;
            const bool was_revealing = model_.reveal_active();
            if (model_.select_next()) {
                if (was_revealing) render();
                (void)persist_selection();
                dirty = true;
            }
        }

        if (!model_.reveal_active() &&
            now_ms - last_refresh_ms >= kAccountRefreshIntervalMs) {
            dirty = refresh_accounts() || dirty;
            last_refresh_ms = now_ms;
        }

        if (dirty) render();
        vTaskDelay(kUiPollInterval);
    }
}

}  // namespace m5auth::device::sticks3
