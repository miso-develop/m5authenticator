#include <cstdio>
#include <cstring>
#include <mutex>
#include <string>
#include <string_view>
#include <vector>

#include "driver/usb_serial_jtag.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "m5auth/core/metadata.hpp"
#include "m5auth/device/sticks3/canonical_device.hpp"
#include "m5auth/device/sticks3/device.hpp"
#include "m5auth/provisioning/canonical_protocol_v2.hpp"
#include "m5auth/provisioning/canonical_v2_state.hpp"
#include "m5auth/provisioning/session_protocol_v2.hpp"
#include "m5auth/registration/registration.hpp"
#include "m5auth/session/protocol_v2.hpp"
#include "m5auth/time/time_service.hpp"
#include "m5auth/time/trusted_time.hpp"
#include "m5auth/totp/generator.hpp"
#include "m5auth/vault_runtime/runtime.hpp"

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

std::uint64_t monotonic_ms() {
    const std::int64_t microseconds = esp_timer_get_time();
    return microseconds <= 0
        ? 0
        : static_cast<std::uint64_t>(microseconds / 1'000);
}

void teardown_transport_session(
    m5auth::provisioning::CanonicalProtocolV2Handler& protocol
) {
    protocol.disconnect();
}

}  // namespace

extern "C" void app_main(void) {
    m5auth::device::sticks3::initialize();
    const auto metadata = m5auth::core::metadata_for(
        m5auth::device::sticks3::kDeviceModel,
        M5AUTH_BUILD_COMMIT
    );

    std::recursive_mutex runtime_access_mutex;

    m5auth::registration::Store registration;
    (void)registration.initialize();

    m5auth::vault_runtime::CompatibleNvsPersistence persistence;
    m5auth::vault_runtime::Runtime runtime(persistence);
    (void)runtime.initialize();

    m5auth::time::TrustedClock trusted_clock;
    m5auth::time::TimeService time_service(
        runtime,
        trusted_clock,
        runtime_access_mutex
    );
    (void)time_service.boot_sync();
    (void)time_service.start_periodic_resync();

    m5auth::totp::VaultGenerator generator(runtime, time_service);
    m5auth::device::sticks3::CanonicalPresence presence;
    m5auth::device::sticks3::CanonicalUiController ui(
        runtime,
        generator,
        time_service,
        runtime_access_mutex,
        presence
    );
    (void)ui.start();

    m5auth::session::protocol_v2::AttemptCoordinator coordinator(presence);
    m5auth::provisioning::CanonicalBindingSource binding_source(
        runtime,
        registration,
        runtime_access_mutex
    );
    m5auth::provisioning::CanonicalVmkSink vmk_sink(
        runtime,
        registration,
        runtime_access_mutex
    );
    m5auth::provisioning::StagedSessionV2Handler session_handler(
        coordinator,
        binding_source,
        vmk_sink
    );
    m5auth::provisioning::CanonicalProtocolV2Handler protocol(
        metadata,
        runtime,
        registration,
        time_service,
        session_handler,
        vmk_sink,
        presence,
        runtime_access_mutex,
        [&ui]() { ui.security_boundary_clear(); }
    );

    std::vector<char> input(
        m5auth::provisioning::kMaxCanonicalV2MessageBytes + 2,
        '\0'
    );

    while (true) {
        protocol.housekeeping(monotonic_ms());

        if (std::fgets(
                input.data(),
                static_cast<int>(input.size()),
                stdin
            ) == nullptr) {
            if (!usb_serial_jtag_is_connected()) {
                teardown_transport_session(protocol);
            }
            m5auth::vault_runtime::secure_zero(input.data(), input.size());
            std::clearerr(stdin);
            vTaskDelay(pdMS_TO_TICKS(20));
            continue;
        }

        std::size_t length = std::strlen(input.data());
        const bool complete_line = length > 0 && input[length - 1] == '\n';
        if (!complete_line) {
            const bool overflow = length == input.size() - 1;
            if (overflow) discard_line_remainder();
            teardown_transport_session(protocol);
            m5auth::vault_runtime::secure_zero(input.data(), input.size());
            if (overflow) {
                write_response(m5auth::provisioning::canonical_v2_message_too_large_response());
            }
            continue;
        }

        while (length > 0 && (input[length - 1] == '\n' || input[length - 1] == '\r')) --length;
        const std::string response = protocol.handle_line(
            std::string_view(input.data(), length),
            monotonic_ms()
        );
        m5auth::vault_runtime::secure_zero(input.data(), input.size());
        write_response(response);
    }
}
