#include <algorithm>
#include <array>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <limits>
#include <mutex>
#include <string>
#include <string_view>
#include <vector>
#include <unistd.h>

#include "cJSON.h"
#include "driver/usb_serial_jtag.h"
#include "esp_attr.h"
#include "esp_system.h"
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

#ifndef M5AUTH_TIMING_DIAGNOSTICS
#define M5AUTH_TIMING_DIAGNOSTICS 0
#endif

#ifndef M5AUTH_TEST_SCREEN_SNAPSHOT
#define M5AUTH_TEST_SCREEN_SNAPSHOT 0
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
constexpr bool kTestScreenSnapshotEnabled = M5AUTH_TEST_SCREEN_SNAPSHOT == 1;
constexpr std::uint32_t kTimingRtcMagic = 0x4d354438U;  // "M5D8"
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

RTC_NOINIT_ATTR RtcTimingDiagnostics g_rtc_timing_diagnostics;
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
    const auto elapsed_us = static_cast<std::uint64_t>(finished_us - started_us);
    ++sample->count;
    sample->last_us = elapsed_us;
    sample->max_us = std::max(sample->max_us, elapsed_us);
    return true;
}

void write_response(
    const std::string& response,
    TimingOperation operation = TimingOperation::kNone
) {
    const bool measure = kTimingDiagnosticsEnabled && operation != TimingOperation::kNone;
    const std::int64_t started_us = measure ? esp_timer_get_time() : 0;

    // stdout is line-buffered and shared with ESP-IDF console logging. Keep the
    // JSON body and its newline in one logical frame and hold the FILE lock across
    // write/flush/fsync so another normal stdout writer cannot enter between them.
    // The USB Serial/JTAG VFS adds its own write lock for stdout/stderr sharing.
    std::string frame;
    frame.reserve(response.size() + 1);
    frame.append(response);
    frame.push_back('\n');

    ::flockfile(stdout);
    const std::size_t fwrite_bytes = std::fwrite(frame.data(), 1, frame.size(), stdout);
    const int fflush_result = std::fflush(stdout);
    // fflush() drains libc buffering. ESP-IDF's USB Serial/JTAG VFS fsync path
    // waits for host pickup and emits the terminating ZLP needed when a transfer
    // lands on an exact 64-byte USB packet boundary.
    (void)::fsync(STDOUT_FILENO);
    const int ferror_value = std::ferror(stdout);
    ::funlockfile(stdout);

    if (!measure || started_us <= 0) return;
    const std::int64_t finished_us = esp_timer_get_time();
    if (finished_us < started_us) return;

    const auto elapsed_us = static_cast<std::uint64_t>(finished_us - started_us);
    auto& sample = g_timing_diagnostics.response_write;
    ++sample.count;
    sample.last_us = elapsed_us;
    sample.max_us = std::max(sample.max_us, elapsed_us);
    sample.operation = static_cast<std::uint64_t>(operation);
    sample.response_bytes = response.size();
    sample.fwrite_ok = fwrite_bytes == frame.size() ? 1 : 0;
    sample.newline_ok = fwrite_bytes == frame.size() && frame.back() == '\n' ? 1 : 0;
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

#if M5AUTH_TEST_SCREEN_SNAPSHOT
constexpr std::string_view kScreenSnapshotOperation = "diagnostics.screen_snapshot";

bool synchronize_screen_snapshot_response_boundary() {
    // A valid diagnostic request proves that a user-space serial listener is now
    // active. First finalize any earlier exact-64-byte Device-to-host transfer,
    // then emit one test-only line delimiter and finalize it before the current
    // JSON response. This never strips, reparses, skips, or retries a current
    // response; it only creates an explicit framing boundary ahead of it.
    ::flockfile(stdout);
    const int pre_fflush_result = std::fflush(stdout);
    const int pre_fsync_result = pre_fflush_result == 0
        ? ::fsync(STDOUT_FILENO)
        : -1;
    const int delimiter_result = pre_fsync_result == 0
        ? std::fputc('\n', stdout)
        : EOF;
    const int delimiter_fflush_result = delimiter_result != EOF
        ? std::fflush(stdout)
        : -1;
    const int delimiter_fsync_result = delimiter_fflush_result == 0
        ? ::fsync(STDOUT_FILENO)
        : -1;
    const int ferror_value = std::ferror(stdout);
    ::funlockfile(stdout);

    return pre_fflush_result == 0 &&
        pre_fsync_result == 0 &&
        delimiter_result != EOF &&
        delimiter_fflush_result == 0 &&
        delimiter_fsync_result == 0 &&
        ferror_value == 0;
}

enum class ScreenSnapshotRequestKind {
    kNotDiagnostic,
    kInvalidDiagnostic,
    kValidDiagnostic,
};

struct ScreenSnapshotRequestParse {
    ScreenSnapshotRequestKind kind{ScreenSnapshotRequestKind::kNotDiagnostic};
    int id{0};
};

bool read_nonnegative_json_int(cJSON* item, int* value) {
    if (value == nullptr || !cJSON_IsNumber(item) || !std::isfinite(item->valuedouble) ||
        item->valuedouble < 0 || item->valuedouble > std::numeric_limits<int>::max()) {
        return false;
    }
    const int parsed = static_cast<int>(item->valuedouble);
    if (static_cast<double>(parsed) != item->valuedouble) return false;
    *value = parsed;
    return true;
}

bool screen_snapshot_intent_hint(std::string_view line) {
    return line.find("\"diagnostics.screen_snapshot\"") != std::string_view::npos;
}

ScreenSnapshotRequestParse parse_screen_snapshot_request(std::string_view line) {
    if (!kTestScreenSnapshotEnabled) return {};

    const bool raw_intent_hint = screen_snapshot_intent_hint(line);
    if (!raw_intent_hint) return {};

    // Only diagnostic candidates are copied/parsed here. Ordinary Protocol-v2
    // requests, which may contain sensitive payloads, never enter this parser.
    // The explicit NUL-terminated copy avoids cJSON version-dependent end-pointer
    // behavior for non-NUL-terminated string_view buffers.
    const std::string diagnostic_json(line);
    cJSON* root = cJSON_ParseWithLengthOpts(
        diagnostic_json.c_str(),
        diagnostic_json.size() + 1,
        nullptr,
        true
    );
    if (root == nullptr || !cJSON_IsObject(root)) {
        if (root != nullptr) cJSON_Delete(root);
        return ScreenSnapshotRequestParse{ScreenSnapshotRequestKind::kInvalidDiagnostic, 0};
    }

    bool diagnostic_intent = false;
    for (cJSON* child = root->child; child != nullptr; child = child->next) {
        if (child->string != nullptr && std::strcmp(child->string, "op") == 0 &&
            cJSON_IsString(child) && child->valuestring != nullptr &&
            std::strcmp(child->valuestring, kScreenSnapshotOperation.data()) == 0) {
            diagnostic_intent = true;
            break;
        }
    }
    if (!diagnostic_intent) {
        cJSON_Delete(root);
        return ScreenSnapshotRequestParse{ScreenSnapshotRequestKind::kInvalidDiagnostic, 0};
    }

    bool seen_v = false;
    bool seen_id = false;
    bool seen_op = false;
    bool seen_params = false;
    bool valid = true;
    int request_id = 0;
    bool request_id_valid = false;

    for (cJSON* child = root->child; child != nullptr; child = child->next) {
        const char* const key = child->string;
        if (key == nullptr) {
            valid = false;
            continue;
        }
        if (std::strcmp(key, "v") == 0) {
            if (seen_v) {
                valid = false;
                continue;
            }
            seen_v = true;
            int version = 0;
            if (!read_nonnegative_json_int(child, &version) || version != 2) valid = false;
        } else if (std::strcmp(key, "id") == 0) {
            if (seen_id) {
                valid = false;
                continue;
            }
            seen_id = true;
            if (read_nonnegative_json_int(child, &request_id)) {
                request_id_valid = true;
            } else {
                valid = false;
            }
        } else if (std::strcmp(key, "op") == 0) {
            if (seen_op) {
                valid = false;
                continue;
            }
            seen_op = true;
            if (!cJSON_IsString(child) || child->valuestring == nullptr ||
                std::strcmp(child->valuestring, kScreenSnapshotOperation.data()) != 0) {
                valid = false;
            }
        } else if (std::strcmp(key, "params") == 0) {
            if (seen_params) {
                valid = false;
                continue;
            }
            seen_params = true;
            if (!cJSON_IsObject(child) || child->child != nullptr) valid = false;
        } else {
            valid = false;
        }
    }

    valid = valid && seen_v && seen_id && seen_op && seen_params;
    cJSON_Delete(root);
    if (!valid) {
        return ScreenSnapshotRequestParse{
            ScreenSnapshotRequestKind::kInvalidDiagnostic,
            request_id_valid ? request_id : 0,
        };
    }
    return ScreenSnapshotRequestParse{
        ScreenSnapshotRequestKind::kValidDiagnostic,
        request_id,
    };
}

const char* screen_snapshot_runtime_state(m5auth::vault_runtime::State state) {
    switch (state) {
        case m5auth::vault_runtime::State::kUnprovisioned: return "unprovisioned";
        case m5auth::vault_runtime::State::kReprovisionRequired: return "reprovision_required";
        case m5auth::vault_runtime::State::kLocked: return "locked";
        case m5auth::vault_runtime::State::kUnlocked: return "unlocked";
        case m5auth::vault_runtime::State::kError: return "error";
    }
    return "error";
}

const char* screen_snapshot_time_readiness(m5auth::time::Readiness readiness) {
    switch (readiness) {
        case m5auth::time::Readiness::kNotSynced: return "not_synced";
        case m5auth::time::Readiness::kReady: return "ready";
        case m5auth::time::Readiness::kStale: return "stale";
    }
    return "not_synced";
}

const char* screen_snapshot_presence_operation(m5auth::session::PresenceOperation operation) {
    switch (operation) {
        case m5auth::session::PresenceOperation::kTrustedBrowserUnlock:
            return "trusted_browser_unlock";
        case m5auth::session::PresenceOperation::kInitialProvisioning:
            return "initial_provisioning";
        case m5auth::session::PresenceOperation::kRecovery:
            return "recovery";
        case m5auth::session::PresenceOperation::kBrowserReplacement:
            return "browser_replacement";
        case m5auth::session::PresenceOperation::kVmkRekey:
            return "vmk_rekey";
        case m5auth::session::PresenceOperation::kFactoryReset:
            return "factory_reset";
    }
    return "none";
}

const char* screen_snapshot_mode(m5auth::device::sticks3::ScreenMode mode) {
    switch (mode) {
        case m5auth::device::sticks3::ScreenMode::kUnlockRequest: return "unlock_request";
        case m5auth::device::sticks3::ScreenMode::kVaultUnavailable: return "vault_unavailable";
        case m5auth::device::sticks3::ScreenMode::kOpenWeb: return "open_web";
        case m5auth::device::sticks3::ScreenMode::kNoAccounts: return "no_accounts";
        case m5auth::device::sticks3::ScreenMode::kOtpRevealed: return "otp_revealed";
        case m5auth::device::sticks3::ScreenMode::kAccountView: return "account_view";
    }
    return "open_web";
}

std::string screen_snapshot_error_response(int request_id, const char* code) {
    std::array<char, 192> buffer{};
    const int written = std::snprintf(
        buffer.data(),
        buffer.size(),
        "{\"v\":2,\"id\":%d,\"ok\":false,\"error\":{\"code\":\"%s\"}}",
        request_id,
        code
    );
    if (written <= 0 || static_cast<std::size_t>(written) >= buffer.size()) {
        return R"({"v":2,"id":0,"ok":false,"error":{"code":"internal_error"}})";
    }
    return std::string(buffer.data(), static_cast<std::size_t>(written));
}

std::string screen_snapshot_response(
    int request_id,
    const m5auth::device::sticks3::ScreenSnapshot& snapshot
) {
    std::array<char, 512> buffer{};
    const char* const presence_operation = snapshot.presence.active
        ? screen_snapshot_presence_operation(snapshot.presence.operation)
        : "none";
    const int written = std::snprintf(
        buffer.data(),
        buffer.size(),
        "{\"v\":2,\"id\":%d,\"ok\":true,\"data\":{" 
        "\"runtime_state\":\"%s\","
        "\"trusted_time_readiness\":\"%s\","
        "\"presence\":{\"active\":%s,\"confirmed\":%s,\"operation\":\"%s\"},"
        "\"screen_mode\":\"%s\"}}",
        request_id,
        screen_snapshot_runtime_state(snapshot.runtime_state),
        screen_snapshot_time_readiness(snapshot.trusted_time_readiness),
        snapshot.presence.active ? "true" : "false",
        snapshot.presence.confirmed ? "true" : "false",
        presence_operation,
        screen_snapshot_mode(snapshot.screen_mode)
    );
    if (written <= 0 || static_cast<std::size_t>(written) >= buffer.size()) {
        return screen_snapshot_error_response(request_id, "internal_error");
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
    initialize_timing_diagnostics_persistence();

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
#if M5AUTH_TEST_SCREEN_SNAPSHOT
        const ScreenSnapshotRequestParse snapshot_request = parse_screen_snapshot_request(request);
        if (snapshot_request.kind != ScreenSnapshotRequestKind::kNotDiagnostic) {
            std::string response;
            if (snapshot_request.kind == ScreenSnapshotRequestKind::kInvalidDiagnostic) {
                response = screen_snapshot_error_response(snapshot_request.id, "invalid_request");
            } else {
                m5auth::device::sticks3::ScreenSnapshot snapshot{};
                if (!ui.screen_snapshot(&snapshot)) {
                    response = screen_snapshot_error_response(
                        snapshot_request.id,
                        "snapshot_not_ready"
                    );
                } else {
                    response = screen_snapshot_response(snapshot_request.id, snapshot);
                }
            }
            m5auth::vault_runtime::secure_zero(input.data(), input.size());
            buffered_input = 0;
            if (!synchronize_screen_snapshot_response_boundary()) {
                // Fail closed without emitting the current JSON frame. Returning
                // stops this protocol task; the Device UI/runtime tasks remain,
                // while the Human helper times out rather than accepting an
                // ambiguously framed response.
                return;
            }
            write_response(response);
            continue;
        }
#endif
        const TimingOperation timing_operation = kTimingDiagnosticsEnabled
            ? classify_timing_operation(request)
            : TimingOperation::kNone;
        const std::int64_t timing_started_us = timing_operation == TimingOperation::kNone
            ? 0
            : esp_timer_get_time();

        const std::string response = protocol.handle_line(
            request,
            monotonic_ms()
        );

        const bool timing_recorded = kTimingDiagnosticsEnabled
            ? record_timing(timing_operation, timing_started_us)
            : false;
        if (timing_recorded) {
            persist_timing_diagnostics_to_rtc();
        }

        m5auth::vault_runtime::secure_zero(input.data(), input.size());
        buffered_input = 0;
        write_response(response, timing_operation);
    }
}