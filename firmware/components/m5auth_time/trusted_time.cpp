#include "m5auth/time/trusted_time.hpp"

#include <limits>

namespace m5auth::time {
namespace {

std::int64_t elapsed_us(
    std::int64_t now_monotonic_us,
    std::int64_t base_monotonic_us
) {
    if (now_monotonic_us < base_monotonic_us) {
        return -1;
    }
    return now_monotonic_us - base_monotonic_us;
}

}  // namespace

void TrustedClock::mark_synchronized(
    std::uint64_t unix_seconds,
    std::int64_t monotonic_us,
    Source source
) {
    std::lock_guard<std::mutex> lock(mutex_);
    synchronized_ = true;
    base_unix_seconds_ = unix_seconds;
    base_monotonic_us_ = monotonic_us;
    source_ = source;
}

Snapshot TrustedClock::snapshot(std::int64_t monotonic_us) const {
    std::lock_guard<std::mutex> lock(mutex_);
    Snapshot result;
    if (!synchronized_) {
        return result;
    }

    result.source = source_;
    result.last_sync_unix_seconds = base_unix_seconds_;

    const std::int64_t elapsed = elapsed_us(monotonic_us, base_monotonic_us_);
    if (elapsed < 0) {
        result.readiness = Readiness::kStale;
        result.resync_due = true;
        return result;
    }

    result.age_seconds = elapsed / 1'000'000;
    result.resync_due =
        elapsed >= kResyncIntervalSeconds * 1'000'000LL;
    result.readiness =
        elapsed > kStaleAfterSeconds * 1'000'000LL
            ? Readiness::kStale
            : Readiness::kReady;
    return result;
}

bool TrustedClock::current_unix_seconds(
    std::int64_t monotonic_us,
    std::uint64_t* unix_seconds
) const {
    if (unix_seconds == nullptr) {
        return false;
    }

    std::lock_guard<std::mutex> lock(mutex_);
    if (!synchronized_) {
        return false;
    }

    const std::int64_t elapsed = elapsed_us(monotonic_us, base_monotonic_us_);
    if (elapsed < 0 || elapsed > kStaleAfterSeconds * 1'000'000LL) {
        return false;
    }

    const std::uint64_t elapsed_seconds =
        static_cast<std::uint64_t>(elapsed / 1'000'000);
    if (base_unix_seconds_ >
        std::numeric_limits<std::uint64_t>::max() - elapsed_seconds) {
        return false;
    }
    *unix_seconds = base_unix_seconds_ + elapsed_seconds;
    return true;
}

const char* readiness_name(Readiness readiness) {
    switch (readiness) {
        case Readiness::kNotSynced:
            return "not_synced";
        case Readiness::kReady:
            return "ready";
        case Readiness::kStale:
            return "stale";
    }
    return "unknown";
}

const char* source_name(Source source) {
    switch (source) {
        case Source::kNone:
            return "none";
        case Source::kNtp:
            return "ntp";
        case Source::kUsb:
            return "usb";
    }
    return "none";
}

}  // namespace m5auth::time
