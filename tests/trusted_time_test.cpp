#include <cassert>
#include <cstdint>

#include "m5auth/time/trusted_time.hpp"

using m5auth::time::Readiness;
using m5auth::time::Source;
using m5auth::time::TrustedClock;

namespace {
constexpr std::int64_t kSecondUs = 1'000'000LL;

void starts_fail_closed() {
    TrustedClock clock;
    const auto status = clock.snapshot(10 * kSecondUs);
    assert(status.readiness == Readiness::kNotSynced);
    assert(status.source == Source::kNone);
    assert(!status.resync_due);
    std::uint64_t now = 0;
    assert(!clock.current_unix_seconds(10 * kSecondUs, &now));
}

void ready_resync_and_stale_boundaries() {
    TrustedClock clock;
    constexpr std::uint64_t base_unix = 2'000'000'000ULL;
    constexpr std::int64_t base_mono = 5 * kSecondUs;
    clock.mark_synchronized(base_unix, base_mono, Source::kNtp);
    auto status = clock.snapshot(base_mono);
    assert(status.readiness == Readiness::kReady && !status.resync_due);
    const auto six_hours = base_mono + m5auth::time::kResyncIntervalSeconds * kSecondUs;
    status = clock.snapshot(six_hours);
    assert(status.readiness == Readiness::kReady && status.resync_due);
    const auto exactly_24h = base_mono + m5auth::time::kStaleAfterSeconds * kSecondUs;
    assert(clock.snapshot(exactly_24h).readiness == Readiness::kReady);
    assert(clock.snapshot(exactly_24h + 1).readiness == Readiness::kStale);
    std::uint64_t current = 0;
    assert(clock.current_unix_seconds(six_hours, &current));
    assert(current == base_unix + static_cast<std::uint64_t>(m5auth::time::kResyncIntervalSeconds));
    assert(!clock.current_unix_seconds(exactly_24h + 1, &current));
}

void usb_resync_replaces_trusted_anchor() {
    TrustedClock clock;
    clock.mark_synchronized(1'900'000'000ULL, 1'000, Source::kNtp);
    clock.mark_synchronized(2'000'000'000ULL, 2'000, Source::kUsb);
    const auto status = clock.snapshot(2'000);
    assert(status.readiness == Readiness::kReady);
    assert(status.source == Source::kUsb);
    assert(status.last_sync_unix_seconds == 2'000'000'000ULL);
}

void monotonic_regression_fails_closed() {
    TrustedClock clock;
    clock.mark_synchronized(2'000'000'000ULL, 10'000, Source::kUsb);
    const auto status = clock.snapshot(9'999);
    assert(status.readiness == Readiness::kStale && status.resync_due);
}
}

int main() {
    starts_fail_closed();
    ready_resync_and_stale_boundaries();
    usb_resync_replaces_trusted_anchor();
    monotonic_regression_fails_closed();
    return 0;
}
