#include "m5auth/device/sticks3/device.hpp"

#include <cstdio>

#include "M5Unified.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

namespace m5auth::device::sticks3 {

bool is_expected_hardware() {
    return M5.getBoard() == m5::board_t::board_M5StickS3;
}

[[noreturn]] void halt_unexpected_hardware() {
    std::fprintf(
        stderr,
        "M5Authenticator refused to start: runtime hardware is not M5StickS3 (board=%d).\n",
        static_cast<int>(M5.getBoard())
    );
    std::fflush(stderr);

    while (true) {
        vTaskDelay(pdMS_TO_TICKS(1000));
    }
}

}  // namespace m5auth::device::sticks3
