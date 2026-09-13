#include <algorithm>
#include <array>
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

#ifdef M5AUTH_TIMING_DIAGNOSTICS

enum class TimingOperation {
    kNone,
    kSessionComplete,
    kVaultInstall,
    kHello,
};

struct TimingSample {
    std::uint64_t count{0};
    std::uint64_t last_us{0};
    std::uint64_t max_us{0};
};

struct TimingDiagnostics {
    TimingSample session_complete{};
    TimingSample vault_install{};
    TimingSample hello{};
};

TimingDiagnostics g_timing_diagnostics{};

constexpr std::string_view kTimingDiagnosticsQuery =
    R"({"v":2,"id":9001,"op":"diagnostics.timing","params":{}})";

TimingOperation classify_timing_operation(std::string_view line) {
    if (line.find("\"op\":\"session.complete\"") != std::string_view::npos) {
        return TimingOperation::kSessionComplete;
    }
    if (line.find("\"op\":\"vault.install\"") != std::string_view::npos) {
        return TimingOperation::kVaultInstall;
    }
    if (line.find("\"op\":\"hello\"") != std::string_view::npos) {
        return TimingOperation::kHello;
    }
    return TimingOperation::kNone;
}

TimingSample* timing_sample(TimingOperation operation) {
    switch (operation) {
        case TimingOperation::kSessionComplete:
            return &g_timing_diagnostics.session_complete;
        case TimingOperation::kVaultInstall:
            return &g_timing_diagnostics.vault_install;
        case TimingOperation::kHello:
            return &g_timing_diagnostics.hello;
        case TimingOperation::kNone:
            return nullptr;
    }
    return nullptr;
}

void record_timing(TimingOperation operation, std::int64_t started_us) {
    TimingSample* sample = timing_sample(operation);
    if (sample == nullptr || started_us <= 0) return;
    const std::int64_t finished_us = esp_timer_get_time();
    if (finished_us < started_us) return;
    const auto elapsed_us = static_cast<std::uint64_t>(finished_us - started_us);
    ++sample->count;
    sample->last_us = elapsed_us;
    sample->max_us = std::max(sample->max_us, elapsed_us);
}

std::string timing_diagnostics_response() {
    std::array<char, 512> buffer{};
    const int written = std::snprintf(
        buffer.data(),
        buffer.size(),
        "{\"v\":2,\"id\":9001,\"ok\":true,\"data\":{"
        "\"session_complete\":{\"count\":%llu,\"last_us\":%llu,\"max_us\":%llu},"
        "\"vault_install\":{\"count\":%llu,\"last_us\":%llu,\"max_us\":%llu},"
        "\"hello\":{\"count\":%llu,\"last_us\":%llu,\"max_us\":%llu}}}",
        static_cast<unsigned long long>(g_timing_diagnostics.session_complete.count),
        static_cast<unsigned long long>(g_timing_diagnostics.session_complete.last_us),
        static_cast<unsigned long long>(g_timing_diagnostics.session_complete.max_us),
        static_cast<unsigned long long>(g_timing_diagnostics.vault_install.count),
        static_cast<unsigned long long>(g_timing_diagnostics.vault_install.last_us),
        static_cast<unsigned long long>(g_timing_diagnostics.vault_install.max_us),
        static_cast<unsigned long long>(g_timing_diagnostics.hello.count),
        static_cast<unsigned long long>(g_timing_diagnostics.hello.last_us),
        static_cast<unsigned long long>(g_timing_diagnostics.hello.max_us)
    );
    if (written <= 0 || static_cast<std::size_t>(written) >= buffer.size()) {
        return R"({"v":2,"id":9001,"ok":false,"error":{"code":"internal_error"}})";
    }
    return std::string(buffer.data(), static_cast<std::size_t>(written));
}

#endif

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
        const std::string_view request(input.data(), length);

#ifdef M5AUTH_TIMING_DIAGNOSTICS
        if (request == kTimingDiagnosticsQuery) {
            m5auth::vault_runtime::secure_zero(input.data(), input.size());
            write_response(timing_diagnostics_response());
            continue;
        }
        const TimingOperation timing_operation = classify_timing_operation(request);
        const std::int64_t timing_started_us = timing_operation == TimingOperation::kNone
            ? 0
            : esp_timer_get_time();
#endif

        const std::string response = protocol.handle_line(
            request,
            monotonic_ms()
        );

#ifdef M5AUTH_TIMING_DIAGNOSTICS
        record_timing(timing_operation, timing_started_us);
#endif

        m5auth::vault_runtime::secure_zero(input.data(), input.size());
        write_response(response);
    }
}
