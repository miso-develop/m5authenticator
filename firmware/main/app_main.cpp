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
#include "m5auth/device/sticks3/production_security.hpp"
#include "m5auth/provisioning/protocol.hpp"
#include "m5auth/provisioning/security_protocol.hpp"
#include "m5auth/storage/storage.hpp"
#include "m5auth/time/time_service.hpp"
#include "m5auth/time/trusted_time.hpp"
#include "m5auth/totp/generator.hpp"
#include "sdkconfig.h"

#ifndef M5AUTH_BUILD_COMMIT
#define M5AUTH_BUILD_COMMIT "unknown"
#endif

namespace {

enum class ReadResult { kNone, kReady, kTooLarge };

void write_response(const std::string& response) {
    std::fwrite(response.data(), 1, response.size(), stdout);
    std::fputc('\n', stdout);
    std::fflush(stdout);
}

void discard_line_remainder() {
    int ch = 0;
    do { ch = std::fgetc(stdin); } while (ch != '\n' && ch != EOF);
}

ReadResult read_request(
    std::array<char, m5auth::provisioning::kMaxMessageBytes + 2>* input,
    std::size_t* length
) {
    if (input == nullptr || length == nullptr) return ReadResult::kNone;
    if (std::fgets(input->data(), static_cast<int>(input->size()), stdin) == nullptr) {
        std::clearerr(stdin);
        vTaskDelay(pdMS_TO_TICKS(20));
        return ReadResult::kNone;
    }

    *length = std::strlen(input->data());
    const bool complete_line = *length > 0 && (*input)[*length - 1] == '\n';
    if (!complete_line && *length == input->size() - 1) {
        discard_line_remainder();
        return ReadResult::kTooLarge;
    }
    while (*length > 0 && ((*input)[*length - 1] == '\n' || (*input)[*length - 1] == '\r')) {
        --(*length);
    }
    return ReadResult::kReady;
}

}  // namespace

extern "C" void app_main(void) {
    m5auth::device::sticks3::initialize();
    const auto metadata = m5auth::core::metadata_for(
        m5auth::device::sticks3::kDeviceModel,
        M5AUTH_BUILD_COMMIT
    );

#if CONFIG_M5AUTH_SECURITY_BACKEND_PRODUCTION
    m5auth::storage::HmacEfuseSecurityBackend security_backend(
        static_cast<std::uint8_t>(CONFIG_M5AUTH_HMAC_KEY_ID)
    );
#else
    m5auth::storage::DevSecurityBackend security_backend;
#endif
    m5auth::storage::Store store(security_backend);
    (void)store.initialize();

    std::array<char, m5auth::provisioning::kMaxMessageBytes + 2> input{};

#if CONFIG_M5AUTH_SECURITY_BACKEND_PRODUCTION
    if (!store.ready()) {
        m5auth::storage::ProductionSecurityStatus security{};
        (void)store.production_security_status(&security);
        m5auth::device::sticks3::show_production_security_setup(
            security,
            store.initialization_status()
        );

        m5auth::provisioning::SecuritySession security_session(
            metadata,
            store,
            []() { return m5auth::device::sticks3::confirm_production_security(); }
        );

        while (!store.ready()) {
            std::size_t length = 0;
            const ReadResult result = read_request(&input, &length);
            if (result == ReadResult::kNone) continue;
            if (result == ReadResult::kTooLarge) {
                m5auth::storage::secure_zero(input.data(), input.size());
                write_response(m5auth::provisioning::message_too_large_response());
                continue;
            }

            const std::string response = security_session.handle_line(
                std::string_view(input.data(), length)
            );
            m5auth::storage::secure_zero(input.data(), input.size());
            write_response(response);

            if (!store.ready()) {
                (void)store.production_security_status(&security);
                m5auth::device::sticks3::show_production_security_setup(
                    security,
                    store.initialization_status()
                );
            }
        }
    }
#endif

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
    while (true) {
        std::size_t length = 0;
        const ReadResult result = read_request(&input, &length);
        if (result == ReadResult::kNone) continue;
        if (result == ReadResult::kTooLarge) {
            m5auth::storage::secure_zero(input.data(), input.size());
            write_response(m5auth::provisioning::message_too_large_response());
            continue;
        }

        std::string response;
        {
            std::lock_guard<std::mutex> lock(storage_access_mutex);
            response = session.handle_line(std::string_view(input.data(), length));
        }
        m5auth::storage::secure_zero(input.data(), input.size());
        write_response(response);
    }
}
