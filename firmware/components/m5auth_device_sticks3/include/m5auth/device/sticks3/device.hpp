#pragma once

#include <mutex>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "m5auth/device/sticks3/ui_model.hpp"
#include "m5auth/storage/storage.hpp"
#include "m5auth/time/time_service.hpp"
#include "m5auth/totp/generator.hpp"

namespace m5auth::device::sticks3 {

inline constexpr char kDeviceModel[] = "M5StickS3";

void initialize();
bool is_expected_hardware();
[[noreturn]] void halt_unexpected_hardware();

class UiController {
public:
    UiController(
        storage::Store& store,
        totp::Generator& generator,
        time::TimeService& time_service,
        std::mutex& storage_access_mutex
    );

    UiController(const UiController&) = delete;
    UiController& operator=(const UiController&) = delete;

    bool start();

private:
    static void task_entry(void* context);
    void run();
    bool refresh_accounts();
    bool persist_selection();
    void render();

    storage::Store& store_;
    totp::Generator& generator_;
    time::TimeService& time_service_;
    std::mutex& storage_access_mutex_;
    UiModel model_;
    TaskHandle_t task_{nullptr};
    bool storage_error_{false};
    totp::GenerateResult last_generate_result_{totp::GenerateResult::kOk};
};

}  // namespace m5auth::device::sticks3
