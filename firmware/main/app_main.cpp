#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <string>
#include <string_view>
#include <vector>

#include "driver/usb_serial_jtag.h"
#include "esp_attr.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "hal/usb_serial_jtag_ll.h"
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

#ifndef M5AUTH_TIMING_DIAGNOSTICS
#define M5AUTH_TIMING_DIAGNOSTICS 0
#endif

#ifndef M5AUTH_TX_BOUNDARY_DIAGNOSTICS
#define M5AUTH_TX_BOUNDARY_DIAGNOSTICS 0
#endif

namespace {

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

constexpr bool kTimingDiagnosticsEnabled = M5AUTH_TIMING_DIAGNOSTICS == 1;
constexpr bool kTxBoundaryDiagnosticsEnabled = M5AUTH_TX_BOUNDARY_DIAGNOSTICS == 1;
constexpr std::uint32_t kTimingRtcMagic = 0x4d354438U;  // "M5D8"
constexpr std::uint32_t kTxBoundaryRtcMagic = 0x4d355458U;  // "M5TX"
constexpr std::size_t kTimingBuildBytes = 16;

enum class TimingOperation {
    kNone,
    kSessionBegin,
    kSessionAuthorize,
    kSessionStatus,
    kSessionComplete,
    kVaultInstall,
    kHello,
};

enum class TxBoundaryStage : std::uint64_t {
    kNone = 0,
    kStatusReceived = 1,
    kHandlerComplete = 2,
    kInputWiped = 3,
    kFwriteComplete = 4,
    kNewlineComplete = 5,
    kFlushComplete = 6,
};

struct TimingSample {
    std::uint64_t count{0};
    std::uint64_t last_us{0};
    std::uint64_t max_us{0};
};

struct ResponseWriteDiagnostics {
    std::uint64_t count{0};
    std::uint64_t last_us{0};
    std::uint64_t max_us{0};
    std::uint64_t operation{0};
    std::uint64_t response_bytes{0};
    std::uint64_t fwrite_ok{0};
    std::uint64_t newline_ok{0};
    std::uint64_t fflush_ok{0};
    std::uint64_t ferror_value{0};
};

struct TimingDiagnostics {
    TimingSample session_begin{};
    TimingSample session_authorize{};
    TimingSample session_status{};
    TimingSample session_complete{};
    TimingSample vault_install{};
    TimingSample hello{};
    ResponseWriteDiagnostics response_write{};
};

struct RtcTimingDiagnostics {
    std::uint32_t magic;
    char build[kTimingBuildBytes];
    std::uint64_t values[27];
    std::uint32_t magic_tail;
};

struct RtcTxBoundaryDiagnostics {
    std::uint32_t magic;
    char build[kTimingBuildBytes];
    std::uint64_t count;
    std::uint64_t stage;
    std::uint64_t handler_us;
    std::uint64_t input_wipe_us;
    std::uint64_t fwrite_us;
    std::uint64_t newline_us;
    std::uint64_t fflush_us;
    std::uint64_t total_write_us;
    std::uint64_t response_bytes;
    std::uint64_t fwrite_bytes;
    std::uint64_t newline_ok;
    std::uint64_t fflush_ok;
    std::uint64_t ferror_value;
    std::uint64_t connected_before_write;
    std::uint64_t connected_after_fwrite;
    std::uint64_t connected_after_newline;
    std::uint64_t connected_after_flush;
    std::uint64_t txfifo_before_write;
    std::uint64_t txfifo_after_fwrite;
    std::uint64_t txfifo_after_newline;
    std::uint64_t txfifo_after_flush;
    std::uint64_t stack_hwm_before_write;
    std::uint64_t stack_hwm_after_flush;
    std::uint32_t magic_tail;
};

RTC_NOINIT_ATTR RtcTimingDiagnostics g_rtc_timing_diagnostics;
RTC_NOINIT_ATTR RtcTxBoundaryDiagnostics g_rtc_tx_boundary_diagnostics;
TimingDiagnostics g_timing_diagnostics{};

bool timing_rtc_build_matches() {
    if (g_rtc_timing_diagnostics.magic != kTimingRtcMagic ||
        g_rtc_timing_diagnostics.magic_tail != ~kTimingRtcMagic) {
        return false;
    }
    std::array<char, kTimingBuildBytes> expected{};
    std::snprintf(expected.data(), expected.size(), "%s", M5AUTH_BUILD_COMMIT);
    return std::memcmp(
        g_rtc_timing_diagnostics.build,
        expected.data(),
        expected.size()
    ) == 0;
}

bool tx_boundary_rtc_build_matches() {
    if (g_rtc_tx_boundary_diagnostics.magic != kTxBoundaryRtcMagic ||
        g_rtc_tx_boundary_diagnostics.magic_tail != ~kTxBoundaryRtcMagic) {
        return false;
    }
    std::array<char, kTimingBuildBytes> expected{};
    std::snprintf(expected.data(), expected.size(), "%s", M5AUTH_BUILD_COMMIT);
    return std::memcmp(
        g_rtc_tx_boundary_diagnostics.build,
        expected.data(),
        expected.size()
    ) == 0;
}

void initialize_tx_boundary_snapshot() {
    if (!kTxBoundaryDiagnosticsEnabled || tx_boundary_rtc_build_matches()) return;
    std::memset(&g_rtc_tx_boundary_diagnostics, 0, sizeof(g_rtc_tx_boundary_diagnostics));
    g_rtc_tx_boundary_diagnostics.magic = kTxBoundaryRtcMagic;
    std::snprintf(
        g_rtc_tx_boundary_diagnostics.build,
        sizeof(g_rtc_tx_boundary_diagnostics.build),
        "%s",
        M5AUTH_BUILD_COMMIT
    );
    g_rtc_tx_boundary_diagnostics.magic_tail = ~kTxBoundaryRtcMagic;
}

void begin_tx_boundary_status() {
    if (!kTxBoundaryDiagnosticsEnabled) return;
    const std::uint64_t next_count = g_rtc_tx_boundary_diagnostics.count + 1;
    std::memset(&g_rtc_tx_boundary_diagnostics, 0, sizeof(g_rtc_tx_boundary_diagnostics));
    g_rtc_tx_boundary_diagnostics.magic = kTxBoundaryRtcMagic;
    std::snprintf(
        g_rtc_tx_boundary_diagnostics.build,
        sizeof(g_rtc_tx_boundary_diagnostics.build),
        "%s",
        M5AUTH_BUILD_COMMIT
    );
    g_rtc_tx_boundary_diagnostics.count = next_count;
    g_rtc_tx_boundary_diagnostics.stage = static_cast<std::uint64_t>(TxBoundaryStage::kStatusReceived);
    g_rtc_tx_boundary_diagnostics.magic_tail = ~kTxBoundaryRtcMagic;
}

std::uint64_t elapsed_us(std::int64_t started_us) {
    if (started_us <= 0) return 0;
    const std::int64_t finished_us = esp_timer_get_time();
    return finished_us >= started_us
        ? static_cast<std::uint64_t>(finished_us - started_us)
        : 0;
}

void persist_timing_diagnostics_to_rtc() {
    if (!kTimingDiagnosticsEnabled) return;

    g_rtc_timing_diagnostics.magic = kTimingRtcMagic;
    std::memset(
        g_rtc_timing_diagnostics.build,
        0,
        sizeof(g_rtc_timing_diagnostics.build)
    );
    std::snprintf(
        g_rtc_timing_diagnostics.build,
        sizeof(g_rtc_timing_diagnostics.build),
        "%s",
        M5AUTH_BUILD_COMMIT
    );

    const std::array<std::uint64_t, 27> values{
        g_timing_diagnostics.session_begin.count,
        g_timing_diagnostics.session_begin.last_us,
        g_timing_diagnostics.session_begin.max_us,
        g_timing_diagnostics.session_authorize.count,
        g_timing_diagnostics.session_authorize.last_us,
        g_timing_diagnostics.session_authorize.max_us,
        g_timing_diagnostics.session_status.count,
        g_timing_diagnostics.session_status.last_us,
        g_timing_diagnostics.session_status.max_us,
        g_timing_diagnostics.session_complete.count,
        g_timing_diagnostics.session_complete.last_us,
        g_timing_diagnostics.session_complete.max_us,
        g_timing_diagnostics.vault_install.count,
        g_timing_diagnostics.vault_install.last_us,
        g_timing_diagnostics.vault_install.max_us,
        g_timing_diagnostics.hello.count,
        g_timing_diagnostics.hello.last_us,
        g_timing_diagnostics.hello.max_us,
        g_timing_diagnostics.response_write.count,
        g_timing_diagnostics.response_write.last_us,
        g_timing_diagnostics.response_write.max_us,
        g_timing_diagnostics.response_write.operation,
        g_timing_diagnostics.response_write.response_bytes,
        g_timing_diagnostics.response_write.fwrite_ok,
        g_timing_diagnostics.response_write.newline_ok,
        g_timing_diagnostics.response_write.fflush_ok,
        g_timing_diagnostics.response_write.ferror_value,
    };
    std::copy(values.begin(), values.end(), g_rtc_timing_diagnostics.values);
    g_rtc_timing_diagnostics.magic_tail = ~kTimingRtcMagic;
}

void initialize_timing_diagnostics_persistence() {
    if (!kTimingDiagnosticsEnabled) return;

    if (!timing_rtc_build_matches()) {
        g_timing_diagnostics = TimingDiagnostics{};
        std::memset(&g_rtc_timing_diagnostics, 0, sizeof(g_rtc_timing_diagnostics));
        persist_timing_diagnostics_to_rtc();
        return;
    }

    g_timing_diagnostics.session_begin = TimingSample{
        g_rtc_timing_diagnostics.values[0],
        g_rtc_timing_diagnostics.values[1],
        g_rtc_timing_diagnostics.values[2],
    };
    g_timing_diagnostics.session_authorize = TimingSample{
        g_rtc_timing_diagnostics.values[3],
        g_rtc_timing_diagnostics.values[4],
        g_rtc_timing_diagnostics.values[5],
    };
    g_timing_diagnostics.session_status = TimingSample{
        g_rtc_timing_diagnostics.values[6],
        g_rtc_timing_diagnostics.values[7],
        g_rtc_timing_diagnostics.values[8],
    };
    g_timing_diagnostics.session_complete = TimingSample{
        g_rtc_timing_diagnostics.values[9],
        g_rtc_timing_diagnostics.values[10],
        g_rtc_timing_diagnostics.values[11],
    };
    g_timing_diagnostics.vault_install = TimingSample{
        g_rtc_timing_diagnostics.values[12],
        g_rtc_timing_diagnostics.values[13],
        g_rtc_timing_diagnostics.values[14],
    };
    g_timing_diagnostics.hello = TimingSample{
        g_rtc_timing_diagnostics.values[15],
        g_rtc_timing_diagnostics.values[16],
        g_rtc_timing_diagnostics.values[17],
    };
    g_timing_diagnostics.response_write = ResponseWriteDiagnostics{
        g_rtc_timing_diagnostics.values[18],
        g_rtc_timing_diagnostics.values[19],
        g_rtc_timing_diagnostics.values[20],
        g_rtc_timing_diagnostics.values[21],
        g_rtc_timing_diagnostics.values[22],
        g_rtc_timing_diagnostics.values[23],
        g_rtc_timing_diagnostics.values[24],
        g_rtc_timing_diagnostics.values[25],
        g_rtc_timing_diagnostics.values[26],
    };
}

bool is_timing_diagnostics_query(std::string_view line) {
    if (!kTimingDiagnosticsEnabled || line.size() > 160) return false;
    return line.find("\"v\":2") != std::string_view::npos &&
        line.find("\"id\":9001") != std::string_view::npos &&
        line.find("\"op\":\"diagnostics.timing\"") != std::string_view::npos &&
        line.find("\"params\":{}") != std::string_view::npos;
}

bool is_tx_boundary_diagnostics_query(std::string_view line) {
    if (!kTxBoundaryDiagnosticsEnabled || line.size() > 176) return false;
    return line.find("\"v\":2") != std::string_view::npos &&
        line.find("\"id\":9002") != std::string_view::npos &&
        line.find("\"op\":\"diagnostics.tx_boundary\"") != std::string_view::npos &&
        line.find("\"params\":{}") != std::string_view::npos;
}

TimingOperation classify_timing_operation(std::string_view line) {
    if (line.find("\"op\":\"session.begin\"") != std::string_view::npos) {
        return TimingOperation::kSessionBegin;
    }
    if (line.find("\"op\":\"session.authorize\"") != std::string_view::npos) {
        return TimingOperation::kSessionAuthorize;
    }
    if (line.find("\"op\":\"session.status\"") != std::string_view::npos) {
        return TimingOperation::kSessionStatus;
    }
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

const char* timing_operation_name(TimingOperation operation) {
    switch (operation) {
        case TimingOperation::kSessionBegin: return "session.begin";
        case TimingOperation::kSessionAuthorize: return "session.authorize";
        case TimingOperation::kSessionStatus: return "session.status";
        case TimingOperation::kSessionComplete: return "session.complete";
        case TimingOperation::kVaultInstall: return "vault.install";
        case TimingOperation::kHello: return "hello";
        case TimingOperation::kNone: return "none";
    }
    return "none";
}

TimingSample* timing_sample(TimingOperation operation) {
    switch (operation) {
        case TimingOperation::kSessionBegin:
            return &g_timing_diagnostics.session_begin;
        case TimingOperation::kSessionAuthorize:
            return &g_timing_diagnostics.session_authorize;
        case TimingOperation::kSessionStatus:
            return &g_timing_diagnostics.session_status;
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

bool record_timing(TimingOperation operation, std::int64_t started_us) {
    TimingSample* sample = timing_sample(operation);
    if (sample == nullptr || started_us <= 0) return false;
    const std::int64_t finished_us = esp_timer_get_time();
    if (finished_us < started_us) return false;
    const auto elapsed = static_cast<std::uint64_t>(finished_us - started_us);
    ++sample->count;
    sample->last_us = elapsed;
    sample->max_us = std::max(sample->max_us, elapsed);
    return true;
}

void write_response(
    const std::string& response,
    TimingOperation operation = TimingOperation::kNone
) {
    const bool measure = kTimingDiagnosticsEnabled && operation != TimingOperation::kNone;
    const bool tx_probe = kTxBoundaryDiagnosticsEnabled &&
        operation == TimingOperation::kSessionStatus;
    const std::int64_t started_us = measure ? esp_timer_get_time() : 0;
    const std::int64_t total_write_started_us = tx_probe ? esp_timer_get_time() : 0;

    if (tx_probe) {
        g_rtc_tx_boundary_diagnostics.response_bytes = response.size();
        g_rtc_tx_boundary_diagnostics.connected_before_write =
            usb_serial_jtag_is_connected() ? 1 : 0;
        g_rtc_tx_boundary_diagnostics.txfifo_before_write =
            usb_serial_jtag_ll_txfifo_writable() ? 1 : 0;
        g_rtc_tx_boundary_diagnostics.stack_hwm_before_write =
            static_cast<std::uint64_t>(uxTaskGetStackHighWaterMark(nullptr));
    }

    const std::int64_t fwrite_started_us = tx_probe ? esp_timer_get_time() : 0;
    const std::size_t fwrite_bytes = std::fwrite(response.data(), 1, response.size(), stdout);
    if (tx_probe) {
        g_rtc_tx_boundary_diagnostics.fwrite_us = elapsed_us(fwrite_started_us);
        g_rtc_tx_boundary_diagnostics.fwrite_bytes = fwrite_bytes;
        g_rtc_tx_boundary_diagnostics.connected_after_fwrite =
            usb_serial_jtag_is_connected() ? 1 : 0;
        g_rtc_tx_boundary_diagnostics.txfifo_after_fwrite =
            usb_serial_jtag_ll_txfifo_writable() ? 1 : 0;
        g_rtc_tx_boundary_diagnostics.stage =
            static_cast<std::uint64_t>(TxBoundaryStage::kFwriteComplete);
    }

    const std::int64_t newline_started_us = tx_probe ? esp_timer_get_time() : 0;
    const int newline_result = std::fputc('\n', stdout);
    if (tx_probe) {
        g_rtc_tx_boundary_diagnostics.newline_us = elapsed_us(newline_started_us);
        g_rtc_tx_boundary_diagnostics.newline_ok = newline_result == '\n' ? 1 : 0;
        g_rtc_tx_boundary_diagnostics.connected_after_newline =
            usb_serial_jtag_is_connected() ? 1 : 0;
        g_rtc_tx_boundary_diagnostics.txfifo_after_newline =
            usb_serial_jtag_ll_txfifo_writable() ? 1 : 0;
        g_rtc_tx_boundary_diagnostics.stage =
            static_cast<std::uint64_t>(TxBoundaryStage::kNewlineComplete);
    }

    const std::int64_t fflush_started_us = tx_probe ? esp_timer_get_time() : 0;
    const int fflush_result = std::fflush(stdout);
    const int ferror_value = std::ferror(stdout);
    if (tx_probe) {
        g_rtc_tx_boundary_diagnostics.fflush_us = elapsed_us(fflush_started_us);
        g_rtc_tx_boundary_diagnostics.total_write_us = elapsed_us(total_write_started_us);
        g_rtc_tx_boundary_diagnostics.fflush_ok = fflush_result == 0 ? 1 : 0;
        g_rtc_tx_boundary_diagnostics.ferror_value = ferror_value == 0 ? 0 : 1;
        g_rtc_tx_boundary_diagnostics.connected_after_flush =
            usb_serial_jtag_is_connected() ? 1 : 0;
        g_rtc_tx_boundary_diagnostics.txfifo_after_flush =
            usb_serial_jtag_ll_txfifo_writable() ? 1 : 0;
        g_rtc_tx_boundary_diagnostics.stack_hwm_after_flush =
            static_cast<std::uint64_t>(uxTaskGetStackHighWaterMark(nullptr));
        g_rtc_tx_boundary_diagnostics.stage =
            static_cast<std::uint64_t>(TxBoundaryStage::kFlushComplete);
    }

    if (!measure || started_us <= 0) return;
    const std::int64_t finished_us = esp_timer_get_time();
    if (finished_us < started_us) return;

    const auto elapsed = static_cast<std::uint64_t>(finished_us - started_us);
    auto& sample = g_timing_diagnostics.response_write;
    ++sample.count;
    sample.last_us = elapsed;
    sample.max_us = std::max(sample.max_us, elapsed);
    sample.operation = static_cast<std::uint64_t>(operation);
    sample.response_bytes = response.size();
    sample.fwrite_ok = fwrite_bytes == response.size() ? 1 : 0;
    sample.newline_ok = newline_result == '\n' ? 1 : 0;
    sample.fflush_ok = fflush_result == 0 ? 1 : 0;
    sample.ferror_value = ferror_value == 0 ? 0 : 1;
    persist_timing_diagnostics_to_rtc();
}

std::string timing_diagnostics_response() {
    std::array<char, 1400> buffer{};
    const auto response_operation = static_cast<TimingOperation>(
        g_timing_diagnostics.response_write.operation
    );
    const int written = std::snprintf(
        buffer.data(),
        buffer.size(),
        "{\"v\":2,\"id\":9001,\"ok\":true,\"data\":{"
        "\"session_begin\":{\"count\":%llu,\"last_us\":%llu,\"max_us\":%llu},"
        "\"session_authorize\":{\"count\":%llu,\"last_us\":%llu,\"max_us\":%llu},"
        "\"session_status\":{\"count\":%llu,\"last_us\":%llu,\"max_us\":%llu},"
        "\"session_complete\":{\"count\":%llu,\"last_us\":%llu,\"max_us\":%llu},"
        "\"vault_install\":{\"count\":%llu,\"last_us\":%llu,\"max_us\":%llu},"
        "\"hello\":{\"count\":%llu,\"last_us\":%llu,\"max_us\":%llu},"
        "\"tx_write\":{\"count\":%llu,\"op\":\"%s\",\"response_bytes\":%llu,"
        "\"fwrite_ok\":%llu,\"newline_ok\":%llu,\"fflush_ok\":%llu,"
        "\"ferror\":%llu,\"last_us\":%llu,\"max_us\":%llu},"
        "\"reset_reason\":%d}}",
        static_cast<unsigned long long>(g_timing_diagnostics.session_begin.count),
        static_cast<unsigned long long>(g_timing_diagnostics.session_begin.last_us),
        static_cast<unsigned long long>(g_timing_diagnostics.session_begin.max_us),
        static_cast<unsigned long long>(g_timing_diagnostics.session_authorize.count),
        static_cast<unsigned long long>(g_timing_diagnostics.session_authorize.last_us),
        static_cast<unsigned long long>(g_timing_diagnostics.session_authorize.max_us),
        static_cast<unsigned long long>(g_timing_diagnostics.session_status.count),
        static_cast<unsigned long long>(g_timing_diagnostics.session_status.last_us),
        static_cast<unsigned long long>(g_timing_diagnostics.session_status.max_us),
        static_cast<unsigned long long>(g_timing_diagnostics.session_complete.count),
        static_cast<unsigned long long>(g_timing_diagnostics.session_complete.last_us),
        static_cast<unsigned long long>(g_timing_diagnostics.session_complete.max_us),
        static_cast<unsigned long long>(g_timing_diagnostics.vault_install.count),
        static_cast<unsigned long long>(g_timing_diagnostics.vault_install.last_us),
        static_cast<unsigned long long>(g_timing_diagnostics.vault_install.max_us),
        static_cast<unsigned long long>(g_timing_diagnostics.hello.count),
        static_cast<unsigned long long>(g_timing_diagnostics.hello.last_us),
        static_cast<unsigned long long>(g_timing_diagnostics.hello.max_us),
        static_cast<unsigned long long>(g_timing_diagnostics.response_write.count),
        timing_operation_name(response_operation),
        static_cast<unsigned long long>(g_timing_diagnostics.response_write.response_bytes),
        static_cast<unsigned long long>(g_timing_diagnostics.response_write.fwrite_ok),
        static_cast<unsigned long long>(g_timing_diagnostics.response_write.newline_ok),
        static_cast<unsigned long long>(g_timing_diagnostics.response_write.fflush_ok),
        static_cast<unsigned long long>(g_timing_diagnostics.response_write.ferror_value),
        static_cast<unsigned long long>(g_timing_diagnostics.response_write.last_us),
        static_cast<unsigned long long>(g_timing_diagnostics.response_write.max_us),
        static_cast<int>(esp_reset_reason())
    );
    if (written <= 0 || static_cast<std::size_t>(written) >= buffer.size()) {
        return R"({"v":2,"id":9001,"ok":false,"error":{"code":"internal_error"}})";
    }
    return std::string(buffer.data(), static_cast<std::size_t>(written));
}

std::string tx_boundary_diagnostics_response() {
    std::array<char, 1600> buffer{};
    const int written = std::snprintf(
        buffer.data(),
        buffer.size(),
        "{\"v\":2,\"id\":9002,\"ok\":true,\"data\":{"
        "\"count\":%llu,\"stage\":%llu,\"handler_us\":%llu,\"input_wipe_us\":%llu,"
        "\"fwrite_us\":%llu,\"newline_us\":%llu,\"fflush_us\":%llu,"
        "\"total_write_us\":%llu,\"response_bytes\":%llu,\"fwrite_bytes\":%llu,"
        "\"newline_ok\":%llu,\"fflush_ok\":%llu,\"ferror\":%llu,"
        "\"connected_before_write\":%llu,\"connected_after_fwrite\":%llu,"
        "\"connected_after_newline\":%llu,\"connected_after_flush\":%llu,"
        "\"txfifo_before_write\":%llu,\"txfifo_after_fwrite\":%llu,"
        "\"txfifo_after_newline\":%llu,\"txfifo_after_flush\":%llu,"
        "\"stack_hwm_before_write\":%llu,\"stack_hwm_after_flush\":%llu,"
        "\"reset_reason\":%d}}",
        static_cast<unsigned long long>(g_rtc_tx_boundary_diagnostics.count),
        static_cast<unsigned long long>(g_rtc_tx_boundary_diagnostics.stage),
        static_cast<unsigned long long>(g_rtc_tx_boundary_diagnostics.handler_us),
        static_cast<unsigned long long>(g_rtc_tx_boundary_diagnostics.input_wipe_us),
        static_cast<unsigned long long>(g_rtc_tx_boundary_diagnostics.fwrite_us),
        static_cast<unsigned long long>(g_rtc_tx_boundary_diagnostics.newline_us),
        static_cast<unsigned long long>(g_rtc_tx_boundary_diagnostics.fflush_us),
        static_cast<unsigned long long>(g_rtc_tx_boundary_diagnostics.total_write_us),
        static_cast<unsigned long long>(g_rtc_tx_boundary_diagnostics.response_bytes),
        static_cast<unsigned long long>(g_rtc_tx_boundary_diagnostics.fwrite_bytes),
        static_cast<unsigned long long>(g_rtc_tx_boundary_diagnostics.newline_ok),
        static_cast<unsigned long long>(g_rtc_tx_boundary_diagnostics.fflush_ok),
        static_cast<unsigned long long>(g_rtc_tx_boundary_diagnostics.ferror_value),
        static_cast<unsigned long long>(g_rtc_tx_boundary_diagnostics.connected_before_write),
        static_cast<unsigned long long>(g_rtc_tx_boundary_diagnostics.connected_after_fwrite),
        static_cast<unsigned long long>(g_rtc_tx_boundary_diagnostics.connected_after_newline),
        static_cast<unsigned long long>(g_rtc_tx_boundary_diagnostics.connected_after_flush),
        static_cast<unsigned long long>(g_rtc_tx_boundary_diagnostics.txfifo_before_write),
        static_cast<unsigned long long>(g_rtc_tx_boundary_diagnostics.txfifo_after_fwrite),
        static_cast<unsigned long long>(g_rtc_tx_boundary_diagnostics.txfifo_after_newline),
        static_cast<unsigned long long>(g_rtc_tx_boundary_diagnostics.txfifo_after_flush),
        static_cast<unsigned long long>(g_rtc_tx_boundary_diagnostics.stack_hwm_before_write),
        static_cast<unsigned long long>(g_rtc_tx_boundary_diagnostics.stack_hwm_after_flush),
        static_cast<int>(esp_reset_reason())
    );
    if (written <= 0 || static_cast<std::size_t>(written) >= buffer.size()) {
        return R"({"v":2,"id":9002,"ok":false,"error":{"code":"internal_error"}})";
    }
    return std::string(buffer.data(), static_cast<std::size_t>(written));
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
    initialize_timing_diagnostics_persistence();
    initialize_tx_boundary_snapshot();

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
    std::size_t buffered_input = 0;
    bool discard_oversized_input = false;

    while (true) {
        protocol.housekeeping(monotonic_ms());

        if (discard_oversized_input) {
            if (std::fgets(
                    input.data(),
                    static_cast<int>(input.size()),
                    stdin
                ) == nullptr) {
                if (!usb_serial_jtag_is_connected()) {
                    teardown_transport_session(protocol);
                    discard_oversized_input = false;
                }
                m5auth::vault_runtime::secure_zero(input.data(), input.size());
                std::clearerr(stdin);
                vTaskDelay(pdMS_TO_TICKS(20));
                continue;
            }
            const std::size_t discarded_length = std::strlen(input.data());
            const bool discarded_complete_line =
                discarded_length > 0 && input[discarded_length - 1] == '\n';
            m5auth::vault_runtime::secure_zero(input.data(), input.size());
            std::clearerr(stdin);
            if (discarded_complete_line) {
                discard_oversized_input = false;
            }
            continue;
        }

        if (std::fgets(
                input.data() + buffered_input,
                static_cast<int>(input.size() - buffered_input),
                stdin
            ) == nullptr) {
            if (!usb_serial_jtag_is_connected()) {
                teardown_transport_session(protocol);
                m5auth::vault_runtime::secure_zero(input.data(), input.size());
                buffered_input = 0;
            }
            std::clearerr(stdin);
            vTaskDelay(pdMS_TO_TICKS(20));
            continue;
        }

        buffered_input += std::strlen(input.data() + buffered_input);
        const bool complete_line =
            buffered_input > 0 && input[buffered_input - 1] == '\n';
        if (!complete_line) {
            std::clearerr(stdin);
            if (buffered_input > m5auth::provisioning::kMaxCanonicalV2MessageBytes) {
                teardown_transport_session(protocol);
                m5auth::vault_runtime::secure_zero(input.data(), input.size());
                buffered_input = 0;
                discard_oversized_input = true;
                write_response(m5auth::provisioning::canonical_v2_message_too_large_response());
            } else {
                // USB Serial/JTAG VFS reads are non-blocking. A valid JSON line can
                // arrive in multiple reads, so keep the bounded fragment in RAM
                // until the newline arrives. Disconnect handling above wipes it.
                vTaskDelay(pdMS_TO_TICKS(1));
            }
            continue;
        }

        std::size_t length = buffered_input;
        while (length > 0 && (input[length - 1] == '\n' || input[length - 1] == '\r')) --length;
        if (length > m5auth::provisioning::kMaxCanonicalV2MessageBytes) {
            teardown_transport_session(protocol);
            m5auth::vault_runtime::secure_zero(input.data(), input.size());
            buffered_input = 0;
            write_response(m5auth::provisioning::canonical_v2_message_too_large_response());
            continue;
        }
        const std::string_view request(input.data(), length);

        if (is_timing_diagnostics_query(request)) {
            m5auth::vault_runtime::secure_zero(input.data(), input.size());
            buffered_input = 0;
            write_response(timing_diagnostics_response());
            continue;
        }
        if (is_tx_boundary_diagnostics_query(request)) {
            m5auth::vault_runtime::secure_zero(input.data(), input.size());
            buffered_input = 0;
            write_response(tx_boundary_diagnostics_response());
            continue;
        }

        const TimingOperation classified_operation =
            (kTimingDiagnosticsEnabled || kTxBoundaryDiagnosticsEnabled)
            ? classify_timing_operation(request)
            : TimingOperation::kNone;
        const std::int64_t timing_started_us =
            kTimingDiagnosticsEnabled && classified_operation != TimingOperation::kNone
            ? esp_timer_get_time()
            : 0;
        const bool tx_probe_status = kTxBoundaryDiagnosticsEnabled &&
            classified_operation == TimingOperation::kSessionStatus;
        const std::int64_t tx_handler_started_us = tx_probe_status
            ? esp_timer_get_time()
            : 0;
        if (tx_probe_status) begin_tx_boundary_status();

        const std::string response = protocol.handle_line(
            request,
            monotonic_ms()
        );

        if (tx_probe_status) {
            g_rtc_tx_boundary_diagnostics.handler_us = elapsed_us(tx_handler_started_us);
            g_rtc_tx_boundary_diagnostics.stage =
                static_cast<std::uint64_t>(TxBoundaryStage::kHandlerComplete);
        }

        const bool timing_recorded = kTimingDiagnosticsEnabled
            ? record_timing(classified_operation, timing_started_us)
            : false;
        if (timing_recorded) {
            persist_timing_diagnostics_to_rtc();
        }

        const std::int64_t tx_wipe_started_us = tx_probe_status
            ? esp_timer_get_time()
            : 0;
        m5auth::vault_runtime::secure_zero(input.data(), input.size());
        if (tx_probe_status) {
            g_rtc_tx_boundary_diagnostics.input_wipe_us = elapsed_us(tx_wipe_started_us);
            g_rtc_tx_boundary_diagnostics.stage =
                static_cast<std::uint64_t>(TxBoundaryStage::kInputWiped);
        }
        buffered_input = 0;
        write_response(response, classified_operation);
    }
}
