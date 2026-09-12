#include "m5auth/time/time_service.hpp"

#include <array>
#include <cstring>
#include <string>
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

void wipe_string(std::string* value) {
    if (value == nullptr) return;
    if (!value->empty()) vault_runtime::secure_zero(value->data(), value->size());
    value->clear();
}

}  // namespace

const char* sync_result_code(SyncResult result) {
    switch (result) {
        case SyncResult::kOk: return "ok";
        case SyncResult::kNotConfigured: return "wifi_not_configured";
        case SyncResult::kLocked: return "invalid_state";
        case SyncResult::kNotDue: return "time_sync_not_due";
        case SyncResult::kInvalidTime: return "invalid_time";
        case SyncResult::kNetworkUnavailable: return "network_unavailable";
        case SyncResult::kSyncFailed: return "time_sync_failed";
        case SyncResult::kInternalError: return "time_internal_error";
    }
    return "time_internal_error";
}

TimeService::TimeService(storage::Store& store, TrustedClock& clock)
    : legacy_store_(&store), clock_(clock) {}

TimeService::TimeService(vault_runtime::Runtime& runtime, TrustedClock& clock)
    : vault_runtime_(&runtime), clock_(clock) {}

TimeService::TimeService(
    vault_runtime::Runtime& runtime,
    TrustedClock& clock,
    std::recursive_mutex& runtime_access_mutex
) : vault_runtime_(&runtime),
    runtime_access_mutex_(&runtime_access_mutex),
    clock_(clock) {}

TimeService::~TimeService() {
    if (periodic_task_ != nullptr) {
        vTaskDelete(periodic_task_);
        periodic_task_ = nullptr;
    }
    teardown_network();
}

bool TimeService::ensure_network_initialized() {
    if (network_initialized_) return true;

    esp_err_t result = esp_netif_init();
    if (result != ESP_OK && result != ESP_ERR_INVALID_STATE) return false;
    result = esp_event_loop_create_default();
    if (result != ESP_OK && result != ESP_ERR_INVALID_STATE) return false;

    station_netif_ = esp_netif_create_default_wifi_sta();
    if (station_netif_ == nullptr) return false;

    wifi_init_config_t init = WIFI_INIT_CONFIG_DEFAULT();
    result = esp_wifi_init(&init);
    if (result != ESP_OK) {
        esp_netif_destroy_default_wifi(station_netif_);
        station_netif_ = nullptr;
        return false;
    }
    result = esp_wifi_set_storage(WIFI_STORAGE_RAM);
    if (result != ESP_OK) {
        (void)esp_wifi_deinit();
        esp_netif_destroy_default_wifi(station_netif_);
        station_netif_ = nullptr;
        return false;
    }
    result = esp_wifi_set_mode(WIFI_MODE_STA);
    if (result != ESP_OK) {
        (void)esp_wifi_deinit();
        esp_netif_destroy_default_wifi(station_netif_);
        station_netif_ = nullptr;
        return false;
    }

    network_initialized_ = true;
    return true;
}

void TimeService::teardown_network() {
    if (network_initialized_) {
        (void)esp_wifi_disconnect();
        (void)esp_wifi_stop();
        (void)esp_wifi_deinit();
        network_initialized_ = false;
    }
    if (station_netif_ != nullptr) {
        esp_netif_destroy_default_wifi(station_netif_);
        station_netif_ = nullptr;
    }
}

SyncResult TimeService::connect_and_sync(
    std::string_view ssid,
    std::string_view password
) {
    wifi_config_t config{};
    if (ssid.empty() || ssid.size() > sizeof(config.sta.ssid) ||
        password.empty() || password.size() > sizeof(config.sta.password)) {
        return SyncResult::kSyncFailed;
    }
    if (!ensure_network_initialized()) return SyncResult::kNetworkUnavailable;

    std::memcpy(config.sta.ssid, ssid.data(), ssid.size());
    std::memcpy(config.sta.password, password.data(), password.size());

    esp_err_t result = esp_wifi_set_config(WIFI_IF_STA, &config);
    vault_runtime::secure_zero(&config, sizeof(config));
    if (result != ESP_OK) {
        teardown_network();
        return SyncResult::kSyncFailed;
    }

    result = esp_wifi_start();
    if (result != ESP_OK) {
        teardown_network();
        return SyncResult::kSyncFailed;
    }
    result = esp_wifi_connect();
    if (result != ESP_OK) {
        teardown_network();
        return SyncResult::kSyncFailed;
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
    if (!got_ip) {
        teardown_network();
        return SyncResult::kSyncFailed;
    }

    esp_sntp_config_t sntp_config = ESP_NETIF_SNTP_DEFAULT_CONFIG("pool.ntp.org");
    sntp_config.wait_for_sync = true;
    result = esp_netif_sntp_init(&sntp_config);
    if (result != ESP_OK) {
        teardown_network();
        return SyncResult::kSyncFailed;
    }

    result = esp_netif_sntp_sync_wait(kSntpTimeout);
    struct timeval now {};
    const bool synced = result == ESP_OK && gettimeofday(&now, nullptr) == 0 &&
        now.tv_sec >= 0 && acceptable_unix_seconds(static_cast<std::uint64_t>(now.tv_sec));

    esp_netif_sntp_deinit();
    teardown_network();
    if (!synced) return SyncResult::kSyncFailed;

    // All NTP callers hold sync_mutex_ across this method. Security boundaries
    // use the same mutex and therefore cannot return before this credential-
    // bearing operation has torn down the network and finished this anchor write.
    clock_.mark_synchronized(
        static_cast<std::uint64_t>(now.tv_sec),
        esp_timer_get_time(),
        Source::kNtp
    );
    return SyncResult::kOk;
}

SyncResult TimeService::sync_ntp_once() {
    SyncResult outcome = SyncResult::kNotConfigured;

    if (vault_runtime_ != nullptr) {
        std::string ssid;
        std::string password;
        vault_runtime::Status status = vault_runtime::Status::kIo;
        const auto copy_credentials = [&]() {
            return vault_runtime_->with_wifi(
                [&](const vault::WifiRecord& wifi) {
                    ssid = wifi.ssid;
                    password = wifi.password;
                    return vault_runtime::Status::kOk;
                }
            );
        };
        if (runtime_access_mutex_ != nullptr) {
            std::lock_guard<std::recursive_mutex> access(*runtime_access_mutex_);
            status = copy_credentials();
        } else {
            status = copy_credentials();
        }

        if (status == vault_runtime::Status::kNotFound) {
            wipe_string(&ssid);
            wipe_string(&password);
            return SyncResult::kNotConfigured;
        }
        if (status == vault_runtime::Status::kLocked || status == vault_runtime::Status::kInvalidState) {
            wipe_string(&ssid);
            wipe_string(&password);
            return SyncResult::kLocked;
        }
        if (status != vault_runtime::Status::kOk) {
            wipe_string(&ssid);
            wipe_string(&password);
            return SyncResult::kInternalError;
        }

        outcome = connect_and_sync(ssid, password);
        wipe_string(&ssid);
        wipe_string(&password);
        return outcome;
    }

    if (legacy_store_ == nullptr) return SyncResult::kInternalError;
    const storage::Status status = legacy_store_->with_wifi_credentials(
        [&](std::string_view ssid, std::string_view password) {
            outcome = connect_and_sync(ssid, password);
            return storage::Status::kOk;
        }
    );
    if (status == storage::Status::kNotFound) return SyncResult::kNotConfigured;
    if (status != storage::Status::kOk) return SyncResult::kInternalError;
    return outcome;
}

SyncResult TimeService::boot_sync() {
    std::lock_guard<std::mutex> lock(sync_mutex_);
    SyncResult result = SyncResult::kNotConfigured;
    for (std::size_t attempt = 0; attempt < 3; ++attempt) {
        result = sync_ntp_once();
        if (result == SyncResult::kOk || result == SyncResult::kNotConfigured ||
            result == SyncResult::kLocked || result == SyncResult::kInternalError) {
            return result;
        }
        if (attempt < kBootBackoff.size()) vTaskDelay(kBootBackoff[attempt]);
    }
    return result;
}

SyncResult TimeService::sync_from_usb(std::uint64_t unix_seconds) {
    if (!acceptable_unix_seconds(unix_seconds)) return SyncResult::kInvalidTime;
    std::lock_guard<std::mutex> lock(sync_mutex_);

    const auto apply_sync = [&]() {
        if (vault_runtime_ != nullptr && !vault_runtime_->unlocked()) {
            return SyncResult::kLocked;
        }
        struct timeval value {};
        value.tv_sec = static_cast<time_t>(unix_seconds);
        value.tv_usec = 0;
        if (settimeofday(&value, nullptr) != 0) return SyncResult::kInternalError;
        clock_.mark_synchronized(unix_seconds, esp_timer_get_time(), Source::kUsb);
        return SyncResult::kOk;
    };

    if (vault_runtime_ != nullptr && runtime_access_mutex_ != nullptr) {
        std::lock_guard<std::recursive_mutex> access(*runtime_access_mutex_);
        return apply_sync();
    }
    return apply_sync();
}

SyncResult TimeService::resync_if_due() {
    const std::int64_t before_lock = esp_timer_get_time();
    const Snapshot before = clock_.snapshot(before_lock);
    const bool initial_sync = before.readiness == Readiness::kNotSynced;
    if (!initial_sync && !before.resync_due) return SyncResult::kNotDue;

    std::lock_guard<std::mutex> lock(sync_mutex_);
    const std::int64_t now = esp_timer_get_time();
    const Snapshot current = clock_.snapshot(now);

    if (current.readiness == Readiness::kNotSynced) {
        if (last_initial_attempt_us_ >= 0 &&
            now - last_initial_attempt_us_ <
                static_cast<std::int64_t>(kInitialNtpRetrySeconds * 1'000'000ULL)) {
            return SyncResult::kNotDue;
        }

        const SyncResult result = sync_ntp_once();
        // A LOCKED poll must not consume the initial-sync retry budget. This
        // makes the first periodic poll after a cold-boot unlock immediately
        // eligible for NTP without requiring a prior USB time sync.
        if (result != SyncResult::kLocked) last_initial_attempt_us_ = now;
        if (result == SyncResult::kOk) last_initial_attempt_us_ = -1;
        return result;
    }

    if (!current.resync_due) return SyncResult::kNotDue;
    if (last_periodic_attempt_us_ >= 0 &&
        now - last_periodic_attempt_us_ < kResyncIntervalSeconds * 1'000'000LL) {
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
    if (periodic_task_ != nullptr) return true;
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

void TimeService::prepare_factory_reset() {
    std::lock_guard<std::mutex> lock(sync_mutex_);
    teardown_network();
}

storage::Status TimeService::factory_reset_user_state() {
    std::lock_guard<std::mutex> lock(sync_mutex_);
    teardown_network();
    if (legacy_store_ == nullptr) return storage::Status::kSecurityInvariant;
    return legacy_store_->factory_reset();
}

}  // namespace m5auth::time
