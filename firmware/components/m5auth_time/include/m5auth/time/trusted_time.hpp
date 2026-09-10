#pragma once

#include <cstdint>
#include <mutex>

namespace m5auth::time {

inline constexpr std::int64_t kResyncIntervalSeconds = 6 * 60 * 60;
inline constexpr std::int64_t kStaleAfterSeconds = 24 * 60 * 60;

enum class Readiness {
    kNotSynced,
    kReady,
    kStale,
};

enum class Source {
    kNone,
    kNtp,
    kUsb,
};

struct Snapshot {
    Readiness readiness{Readiness::kNotSynced};
    Source source{Source::kNone};
    std::uint64_t last_sync_unix_seconds{0};
    std::int64_t age_seconds{0};
    bool resync_due{false};
};

class TrustedClock {
public:
    TrustedClock() = default;

    void mark_synchronized(
        std::uint64_t unix_seconds,
        std::int64_t monotonic_us,
        Source source
    );

    Snapshot snapshot(std::int64_t monotonic_us) const;

    bool current_unix_seconds(
        std::int64_t monotonic_us,
        std::uint64_t* unix_seconds
    ) const;

private:
    mutable std::mutex mutex_;
    bool synchronized_{false};
    std::uint64_t base_unix_seconds_{0};
    std::int64_t base_monotonic_us_{0};
    Source source_{Source::kNone};
};

const char* readiness_name(Readiness readiness);
const char* source_name(Source source);

}  // namespace m5auth::time
