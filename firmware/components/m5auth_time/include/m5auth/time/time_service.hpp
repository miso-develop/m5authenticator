#pragma once

#include <cstdint>
#include <mutex>
#include <string_view>
#include <utility>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "m5auth/storage/storage.hpp"
#include "m5auth/time/trusted_time.hpp"
#include "m5auth/vault_runtime/runtime.hpp"

struct esp_netif_obj;

namespace m5auth::time {

inline constexpr std::uint64_t kMinAcceptedUnixSeconds = 1'577'836'800ULL;
inline constexpr std::uint64_t kMaxAcceptedUnixSeconds = 4'102'444'800ULL;
inline constexpr std::uint64_t kInitialNtpRetrySeconds = 60ULL;

enum class SyncResult {
    kOk,
    kNotConfigured,
    kLocked,
    kNotDue,
    kInvalidTime,
    kNetworkUnavailable,
    kSyncFailed,
    kInternalError,
};

const char* sync_result_code(SyncResult result);

class TimeService {
public:
    // Legacy development path retained only for non-canonical tests until #56
    // removes/reclassifies the historical Protocol 1 implementation.
    TimeService(storage::Store& store, TrustedClock& clock);

    // Staged canonical constructor retained for isolated tests. Production #55
    // uses the mutex-aware overload below so UI/protocol/time tasks serialize
    // access to the non-thread-safe Vault Runtime.
    TimeService(vault_runtime::Runtime& runtime, TrustedClock& clock);
    TimeService(
        vault_runtime::Runtime& runtime,
        TrustedClock& clock,
        std::recursive_mutex& runtime_access_mutex
    );
    ~TimeService();

    TimeService(const TimeService&) = delete;
    TimeService& operator=(const TimeService&) = delete;

    SyncResult boot_sync();
    SyncResult sync_from_usb(std::uint64_t unix_seconds);
    SyncResult resync_if_due();

    Snapshot status() const;
    bool current_unix_seconds(std::uint64_t* unix_seconds) const;

    bool start_periodic_resync();

    // Serialize a VMK/secret-destruction boundary with credential-backed NTP.
    // The callback runs while sync_mutex_ is held, after the transient Wi-Fi
    // driver has been torn down. Canonical callers must acquire Runtime state
    // only inside the callback, preserving the global lock order
    // sync_mutex_ -> runtime_access_mutex_. When this call returns, no earlier
    // NTP operation can still retain copied Wi-Fi credentials or later mutate
    // the trusted-time anchor.
    template <typename Callback>
    decltype(auto) with_secret_boundary(Callback&& callback) {
        std::lock_guard<std::mutex> lock(sync_mutex_);
        teardown_network();
        return std::forward<Callback>(callback)();
    }

    // Historical helper kept for the legacy reset path. Canonical callers that
    // also mutate Runtime state must use with_secret_boundary() so teardown and
    // VMK destruction are one serialized lifecycle boundary.
    void prepare_factory_reset();

    // Legacy Protocol 1 helper. Canonical v2 uses the explicit Runtime boundary.
    storage::Status factory_reset_user_state();

private:
    static void periodic_task_entry(void* context);

    SyncResult sync_ntp_once();
    bool ensure_network_initialized();
    SyncResult connect_and_sync(std::string_view ssid, std::string_view password);
    void teardown_network();

    storage::Store* legacy_store_{nullptr};
    vault_runtime::Runtime* vault_runtime_{nullptr};
    std::recursive_mutex* runtime_access_mutex_{nullptr};
    TrustedClock& clock_;
    mutable std::mutex sync_mutex_;
    bool network_initialized_{false};
    esp_netif_obj* station_netif_{nullptr};
    TaskHandle_t periodic_task_{nullptr};
    std::int64_t last_initial_attempt_us_{-1};
    std::int64_t last_periodic_attempt_us_{-1};
};

}  // namespace m5auth::time
