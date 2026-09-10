#include <array>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <string>
#include <string_view>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "m5auth/core/metadata.hpp"
#include "m5auth/device/sticks3/device.hpp"
#include "m5auth/provisioning/protocol.hpp"
#include "m5auth/storage/storage.hpp"
#include "m5auth/time/time_service.hpp"
#include "m5auth/time/trusted_time.hpp"
#include "m5auth/totp/generator.hpp"

#ifndef M5AUTH_BUILD_COMMIT
#define M5AUTH_BUILD_COMMIT "unknown"
#endif

namespace {

void write_response(const std::string& response) {
    std::fwrite(response.data(), 1, response.size(), stdout);
    std::fputc('\n', stdout);
    std::fflush(stdout);
}

void discard_line_remainder() {
    int ch = 0;
    do { ch = std::fgetc(stdin); } while (ch != '\n' && ch != EOF);
}

}  // namespace

extern "C" void app_main(void) {
    m5auth::device::sticks3::initialize();
    const auto metadata = m5auth::core::metadata_for(
        m5auth::device::sticks3::kDeviceModel,
        M5AUTH_BUILD_COMMIT
    );

    m5auth::storage::DevSecurityBackend security_backend;
    m5auth::storage::Store store(security_backend);
    (void)store.initialize();

    m5auth::time::TrustedClock trusted_clock;
    m5auth::time::TimeService time_service(store, trusted_clock);
    (void)time_service.boot_sync();
    (void)time_service.start_periodic_resync();

    std::mutex storage_access_mutex;
    m5auth::totp::Generator generator(store, time_service);
    m5auth::device::sticks3::UiController ui(
        store,
        generator,
        time_service,
        storage_access_mutex
    );
    (void)ui.start();

    m5auth::provisioning::Session session(metadata, store, time_service);
    std::array<char, m5auth::provisioning::kMaxMessageBytes + 2> input{};

    while (true) {
        if (std::fgets(input.data(), static_cast<int>(input.size()), stdin) == nullptr) {
            std::clearerr(stdin);
            vTaskDelay(pdMS_TO_TICKS(20));
            continue;
        }
        std::size_t length = std::strlen(input.data());
        const bool complete_line = length > 0 && input[length - 1] == '\n';
        if (!complete_line && length == input.size() - 1) {
            discard_line_remainder();
            m5auth::storage::secure_zero(input.data(), input.size());
            write_response(m5auth::provisioning::message_too_large_response());
            continue;
        }
        while (length > 0 && (input[length - 1] == '\n' || input[length - 1] == '\r')) --length;

        std::string response;
        {
            std::lock_guard<std::mutex> lock(storage_access_mutex);
            response = session.handle_line(std::string_view(input.data(), length));
        }
        m5auth::storage::secure_zero(input.data(), input.size());
        write_response(response);
    }
}
