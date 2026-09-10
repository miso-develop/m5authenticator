#include "m5auth/device/sticks3/production_security.hpp"

#include <cstdint>

#include "M5Unified.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

namespace m5auth::device::sticks3 {
namespace {

std::uint64_t monotonic_ms() {
    const std::int64_t microseconds = esp_timer_get_time();
    return microseconds <= 0 ? 0 : static_cast<std::uint64_t>(microseconds / 1'000);
}

void heading(const char* line2) {
    M5.Display.clear();
    M5.Display.setTextColor(0xffff, 0x0000);
    M5.Display.setTextSize(1);
    M5.Display.setCursor(0, 0);
    M5.Display.println("M5 Authenticator");
    M5.Display.println(line2);
}

void show_hold_prompt() {
    heading("IRREVERSIBLE EFUSE");
    M5.Display.println("Production security init");
    M5.Display.println("erases DEV auth data.");
    M5.Display.println("HOLD button to confirm");
    M5.Display.println("or wait to cancel.");
}

}  // namespace

void show_production_security_setup(
    const storage::ProductionSecurityStatus& security,
    storage::Status storage_status
) {
    heading("PRODUCTION SETUP");
    M5.Display.printf("HMAC key: %u\n", static_cast<unsigned>(security.hmac_key_id));
    M5.Display.printf("Key: %s\n", storage::efuse_key_state_name(security.key_state));
    M5.Display.printf("Storage: %s\n", storage::status_code(storage_status));
    M5.Display.println("Connect Web Provisioner");
    M5.Display.println("eFuse is NOT changed yet");
}

bool confirm_production_security(std::uint32_t timeout_ms) {
    M5.update();
    bool released_since_entry = !M5.BtnA.isPressed();
    if (released_since_entry) {
        show_hold_prompt();
    } else {
        heading("RELEASE BUTTON FIRST");
        M5.Display.println("A fresh long-hold is");
        M5.Display.println("required to confirm.");
        M5.Display.println("Release, then hold.");
    }

    const std::uint64_t started = monotonic_ms();
    while (monotonic_ms() - started < timeout_ms) {
        M5.update();
        if (!released_since_entry) {
            if (!M5.BtnA.isPressed()) {
                // A button already held when the irreversible confirmation was
                // entered cannot satisfy confirmation. Arm only after a full
                // release, and do not inspect a hold event in this same update.
                released_since_entry = true;
                show_hold_prompt();
            }
        } else if (M5.BtnA.wasHold()) {
            heading("DEVICE CONFIRMED");
            M5.Display.println("Initializing security...");
            return true;
        }
        vTaskDelay(pdMS_TO_TICKS(20));
    }

    heading("CONFIRMATION EXPIRED");
    M5.Display.println("No eFuse change made.");
    M5.Display.println("Return to Web Provisioner.");
    return false;
}

}  // namespace m5auth::device::sticks3
