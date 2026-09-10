#include "m5auth/time/time_service.hpp"

#include <array>
#include <cstring>
#include <sys/time.h>

#include "esp_event.h"
#include "esp_netif.h"
#include "esp_netif_sntp.h"
#include "esp_timer.h"
#include "esp_wifi.h"

namespace m5auth::time {
namespace {

constexpr std::array<TickType_t, 2> kBootBackoff{
    pdMS_TO_TICKS(1'000),
    pdMS_TO_TICKS(3'000),
};
constexpr TickType_t kWifiConnectTimeout = pdMS_TO_TICKS(6'000);
constexpr TickType_t kSntpTimeout = pdMS_TO_TICKS(8'000);
constexpr TickType_t kPollInterval = pdMS_TO_TICKS(100);
constexpr TickType_t kPeriodicPollInterval = pdMS_TO_TICKS(60'000);

bool acceptable_unix_seconds(std::uint64_t unix_seconds) {
    return unix_seconds >= kMinAcceptedUnixSeconds &&
           unix_seconds <= kMaxAcceptedUnixSeconds;
}

}  // namespace

const char* sync_result_code(SyncResult result) {
    switch (result) {
        case SyncResult::kOk: return "ok";
        case SyncResult::kNotConfigured: return "wifi_not_configured";
        case SyncResult::kNotDue: return "time_sync_not_due";
        case SyncResult::kInvalidTime: return "invalid_time";
        case SyncResult::kNetworkUnavailable: return "network_unavailable";
        case SyncResult::kSyncFailed: return "time_sync_failed";
        case SyncResult::kInternalError: return "time_internal_error";
    }
    return "time_internal_error";
}

TimeService::TimeService(storage::Store& store, TrustedClock& clock)
    : store_(store), clock_(clock) {}

TimeService::~TimeService() {
    if (periodic_task_ != nullptr) {
        vTaskDelete(periodic_task_);
        periodic_task_ = nullptr;
    }
    if (network_initialized_) {
        disconnect_wifi();
        (void)esp_wifi_deinit();
    }
}

bool TimeService::ensure_network_initialized() {
    if (network_initialized_) {
        return true;
    }

    esp_err_t result = esp_netif_init();
    if (result != ESP_OK && result != ESP_ERR_INVALID_STATE) {
        return false;
    }
    result = esp_event_loop_create_default();
    if (result != ESP_OK && result != ESP_ERR_INVALID_STATE) {
        return false;
    }

    station_netif_ = esp_netif_create_default_wifi_sta();
    if (station_netif_ == nullptr) {
        return false;
    }

    wifi_init_config_t init = WIFI_INIT_CONFIG_DEFAULT();
    result = esp_wifi_init(&init);
    if (result != ESP_OK) {
        return false;
    }
    result = esp_wifi_set_storage(WIFI_STORAGE_RAM);
    if (result != ESP_OK) {
        return false;
    }
    result = esp_wifi_set_mode(WIFI_MODE_STA);
    if (result != ESP_OK) {
        return false;
    }

    network_initialized_ = true;
    return true;
}

void TimeService::disconnect_wifi() {
    if (!network_initialized_) {
        return;
    }
    (void)esp_wifi_disconnect();
    (void)esp_wifi_stop();
}

bool TimeService::connect_and_sync(
    std::string_view ssid,
    std::string_view password
) {
    if (!ensure_network_initialized()) {
        return false;
    }

    wifi_config_t config{};
    if (ssid.empty() || ssid.size() > sizeof(config.sta.ssid) ||
        password.empty() || password.size() > sizeof(config.sta.password)) {
        return false;
    }
    std::memcpy(config.sta.ssid, ssid.data(), ssid.size());
    std::memcpy(config.sta.password, password.data(), password.size());

    esp_err_t result = esp_wifi_set_config(WIFI_IF_STA, &config);
    storage::secure_zero(config.sta.password, sizeof(config.sta.password));
    if (result != ESP_OK) {
        storage::secure_zero(&config, sizeof(config));
        return false;
    }

    result = esp_wifi_start();
    if (result != ESP_OK) {
        storage::secure_zero(&config, sizeof(config));
        return false;
    }
    result = esp_wifi_connect();
    if (result != ESP_OK) {
        storage::secure_zero(&config, sizeof(config));
        disconnect_wifi();
        return false;
    }

    bool got_ip = false;
    TickType_t waited = 0;
    while (waited < kWifiConnectTimeout) {
        wifi_ap_record_t ap{};
        esp_netif_ip_info_t ip{};
        if (esp_wifi_sta_get_ap_info(&ap) == ESP_OK &&
            esp_netif_get_ip_info(station_netif_, &ip) == ESP_OK &&
            ip.ip.addr != 0) {
            got_ip = true;
            break;
        }
        vTaskDelay(kPollInterval);
        waited += kPollInterval;
    }

    storage::secure_zero(&config, sizeof(config));
    if (!got_ip) {
        disconnect_wifi();
        return false;
    }

    esp_sntp_config_t sntp_config =
        ESP_NETIF_SNTP_DEFAULT_CONFIG("pool.ntp.org");
    sntp_config.wait_for_sync = true;
    result = esp_netif_sntp_init(&sntp_config);
    if (result != ESP_OK) {
        disconnect_wifi();
        return false;
    }

    result = esp_netif_sntp_sync_wait(kSntpTimeout);
    struct timeval now {};
    const bool synced =
        result == ESP_OK && gettimeofday(&now, nullptr) == 0 &&
        now.tv_sec >= 0 &&
        acceptable_unix_seconds(static_cast<std::uint64_t>(now.tv_sec));

    esp_netif_sntp_deinit();
    disconnect_wifi();
    if (!synced) {
        return false;
    }

    clock_.mark_synchronized(
        static_cast<std::uint64_t>(now.tv_sec),
        esp_timer_get_time(),
        Source::kNtp
    );
    return true;
}

SyncResult TimeService::sync_ntp_once() {
    SyncResult outcome = SyncResult::kNotConfigured;
    const storage::Status status = store_.with_wifi_credentials(
        [&](std::string_view ssid, std::string_view password) {
            if (!ensure_network_initialized()) {
                outcome = SyncResult::kNetworkUnavailable;
            } else {
                outcome = connect_and_sync(ssid, password)
                    ? SyncResult::kOk
                    : SyncResult::kSyncFailed;
            }
            return storage::Status::kOk;
        }
    );
    if (status == storage::Status::kNotFound) {
        return SyncResult::kNotConfigured;
    }
    if (status != storage::Status::kOk) {
        return SyncResult::kInternalError;
    }
    return outcome;
}

SyncResult TimeService::boot_sync() {
    std::lock_guard<std::mutex> lock(sync_mutex_);
    SyncResult result = SyncResult::kNotConfigured;
    for (std::size_t attempt = 0; attempt < 3; ++attempt) {
        result = sync_ntp_once();
        if (result == SyncResult::kOk ||
            result == SyncResult::kNotConfigured ||
            result == SyncResult::kInternalError) {
            return result;
        }
        if (attempt < kBootBackoff.size()) {
            vTaskDelay(kBootBackoff[attempt]);
        }
    }
    return result;
}

SyncResult TimeService::sync_from_usb(std::uint64_t unix_seconds) {
    if (!acceptable_unix_seconds(unix_seconds)) {
        return SyncResult::kInvalidTime;
    }
    std::lock_guard<std::mutex> lock(sync_mutex_);
    struct timeval value {};
    value.tv_sec = static_cast<time_t>(unix_seconds);
    value.tv_usec = 0;
    if (settimeofday(&value, nullptr) != 0) {
        return SyncResult::kInternalError;
    }
    clock_.mark_synchronized(unix_seconds, esp_timer_get_time(), Source::kUsb);
    return SyncResult::kOk;
}

SyncResult TimeService::resync_if_due() {
    const std::int64_t before_lock = esp_timer_get_time();
    if (!clock_.snapshot(before_lock).resync_due) {
        return SyncResult::kNotDue;
    }
    std::lock_guard<std::mutex> lock(sync_mutex_);
    const std::int64_t now = esp_timer_get_time();
    if (!clock_.snapshot(now).resync_due) {
        return SyncResult::kNotDue;
    }
    if (last_periodic_attempt_us_ >= 0 &&
        now - last_periodic_attempt_us_ <
            kResyncIntervalSeconds * 1'000'000LL) {
        return SyncResult::kNotDue;
    }
    last_periodic_attempt_us_ = now;
    return sync_ntp_once();
}

Snapshot TimeService::status() const {
    return clock_.snapshot(esp_timer_get_time());
}

bool TimeService::current_unix_seconds(std::uint64_t* unix_seconds) const {
    return clock_.current_unix_seconds(esp_timer_get_time(), unix_seconds);
}

bool TimeService::start_periodic_resync() {
    if (periodic_task_ != nullptr) {
        return true;
    }
    return xTaskCreate(
        &TimeService::periodic_task_entry,
        "m5auth_time_resync",
        6'144,
        this,
        4,
        &periodic_task_
    ) == pdPASS;
}

void TimeService::periodic_task_entry(void* context) {
    auto* service = static_cast<TimeService*>(context);
    while (true) {
        vTaskDelay(kPeriodicPollInterval);
        (void)service->resync_if_due();
    }
}

}  // namespace m5auth::time
