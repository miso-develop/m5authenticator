#pragma once

#include <cstdint>
#include <mutex>
#include <string_view>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "m5auth/storage/storage.hpp"
#include "m5auth/time/trusted_time.hpp"

struct esp_netif_obj;

namespace m5auth::time {

inline constexpr std::uint64_t kMinAcceptedUnixSeconds = 1'577'836'800ULL;
inline constexpr std::uint64_t kMaxAcceptedUnixSeconds = 4'102'444'800ULL;

enum class SyncResult {
    kOk,
    kNotConfigured,
    kNotDue,
    kInvalidTime,
    kNetworkUnavailable,
    kSyncFailed,
    kInternalError,
};

const char* sync_result_code(SyncResult result);

class TimeService {
public:
    TimeService(storage::Store& store, TrustedClock& clock);
    ~TimeService();

    TimeService(const TimeService&) = delete;
    TimeService& operator=(const TimeService&) = delete;

    SyncResult boot_sync();
    SyncResult sync_from_usb(std::uint64_t unix_seconds);
    SyncResult resync_if_due();

    Snapshot status() const;
    bool current_unix_seconds(std::uint64_t* unix_seconds) const;

    bool start_periodic_resync();

private:
    static void periodic_task_entry(void* context);

    SyncResult sync_ntp_once();
    bool ensure_network_initialized();
    bool connect_and_sync(std::string_view ssid, std::string_view password);
    void disconnect_wifi();

    storage::Store& store_;
    TrustedClock& clock_;
    mutable std::mutex sync_mutex_;
    bool network_initialized_{false};
    esp_netif_obj* station_netif_{nullptr};
    TaskHandle_t periodic_task_{nullptr};
    std::int64_t last_periodic_attempt_us_{-1};
};

}  // namespace m5auth::time
