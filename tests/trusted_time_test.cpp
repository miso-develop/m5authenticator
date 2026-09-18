#include <cassert>
#include <cstdint>
#include <string_view>

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

void first_ntp_sample_establishes_current_boot_anchor() {
    TrustedClock clock;
    constexpr std::uint64_t sample = 2'000'000'000ULL;
    constexpr std::int64_t mono = 10 * kSecondUs;
    assert(clock.accept_ntp_sample(sample, mono));
    const auto status = clock.snapshot(mono);
    assert(status.readiness == Readiness::kReady);
    assert(status.source == Source::kNtp);
    assert(status.last_sync_unix_seconds == sample);
    assert(status.age_seconds == 0);
}

void ntp_jump_boundary_is_inclusive_at_300_seconds() {
    constexpr std::uint64_t base = 2'000'000'000ULL;
    constexpr std::int64_t base_mono = 100 * kSecondUs;
    constexpr std::int64_t resync_mono = base_mono + 10 * kSecondUs;
    constexpr std::uint64_t projected = base + 10;

    {
        TrustedClock clock;
        assert(clock.accept_ntp_sample(base, base_mono));
        assert(clock.accept_ntp_sample(
            projected + m5auth::time::kMaxNtpJumpSeconds,
            resync_mono
        ));
        const auto status = clock.snapshot(resync_mono);
        assert(status.last_sync_unix_seconds ==
            projected + m5auth::time::kMaxNtpJumpSeconds);
        assert(status.age_seconds == 0);
    }

    {
        TrustedClock clock;
        assert(clock.accept_ntp_sample(base, base_mono));
        assert(clock.accept_ntp_sample(
            projected - m5auth::time::kMaxNtpJumpSeconds,
            resync_mono
        ));
    }
}

void rejected_ntp_jump_preserves_anchor_and_freshness_lifetime() {
    constexpr std::uint64_t base = 2'000'000'000ULL;
    constexpr std::int64_t base_mono = 1 * kSecondUs;
    TrustedClock clock;
    assert(clock.accept_ntp_sample(base, base_mono));

    const auto six_hours =
        base_mono + m5auth::time::kResyncIntervalSeconds * kSecondUs;
    const auto projected_six_hours =
        base + static_cast<std::uint64_t>(m5auth::time::kResyncIntervalSeconds);
    assert(!clock.accept_ntp_sample(
        projected_six_hours + m5auth::time::kMaxNtpJumpSeconds + 1,
        six_hours
    ));
    auto status = clock.snapshot(six_hours);
    assert(status.readiness == Readiness::kReady);
    assert(status.source == Source::kNtp);
    assert(status.last_sync_unix_seconds == base);
    assert(status.age_seconds == m5auth::time::kResyncIntervalSeconds);

    // Repeated rejected samples do not refresh the anchor or extend READY.
    const auto twelve_hours =
        base_mono + 2 * m5auth::time::kResyncIntervalSeconds * kSecondUs;
    const auto projected_twelve_hours =
        base + static_cast<std::uint64_t>(2 * m5auth::time::kResyncIntervalSeconds);
    assert(!clock.accept_ntp_sample(
        projected_twelve_hours - m5auth::time::kMaxNtpJumpSeconds - 1,
        twelve_hours
    ));
    status = clock.snapshot(twelve_hours);
    assert(status.last_sync_unix_seconds == base);
    assert(status.age_seconds == 2 * m5auth::time::kResyncIntervalSeconds);

    const auto exactly_24h =
        base_mono + m5auth::time::kStaleAfterSeconds * kSecondUs;
    const auto projected_24h =
        base + static_cast<std::uint64_t>(m5auth::time::kStaleAfterSeconds);
    assert(!clock.accept_ntp_sample(
        projected_24h + m5auth::time::kMaxNtpJumpSeconds + 1,
        exactly_24h
    ));
    assert(clock.snapshot(exactly_24h).readiness == Readiness::kReady);
    const auto stale = clock.snapshot(exactly_24h + 1);
    assert(stale.readiness == Readiness::kStale);
    assert(stale.last_sync_unix_seconds == base);
}

void acceptable_ntp_resync_refreshes_anchor_normally() {
    TrustedClock clock;
    constexpr std::uint64_t usb_base = 2'000'000'000ULL;
    constexpr std::int64_t usb_mono = 5 * kSecondUs;
    clock.mark_synchronized(usb_base, usb_mono, Source::kUsb);

    constexpr std::int64_t ntp_mono = usb_mono + 30 * kSecondUs;
    constexpr std::uint64_t ntp_sample = usb_base + 30 + 120;
    assert(clock.accept_ntp_sample(ntp_sample, ntp_mono));
    const auto status = clock.snapshot(ntp_mono);
    assert(status.readiness == Readiness::kReady);
    assert(status.source == Source::kNtp);
    assert(status.last_sync_unix_seconds == ntp_sample);
    assert(status.age_seconds == 0);
    assert(!status.resync_due);
}

void source_authenticity_is_truthful_and_non_cryptographic() {
    assert(std::string_view(m5auth::time::source_authenticity_name(Source::kNone)) == "none");
    assert(std::string_view(m5auth::time::source_authenticity_name(Source::kNtp)) ==
        "unauthenticated_network");
    assert(std::string_view(m5auth::time::source_authenticity_name(Source::kUsb)) ==
        "local_host_asserted");
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
    first_ntp_sample_establishes_current_boot_anchor();
    ntp_jump_boundary_is_inclusive_at_300_seconds();
    rejected_ntp_jump_preserves_anchor_and_freshness_lifetime();
    acceptable_ntp_resync_refreshes_anchor_normally();
    source_authenticity_is_truthful_and_non_cryptographic();
    usb_resync_replaces_trusted_anchor();
    monotonic_regression_fails_closed();
    return 0;
}
