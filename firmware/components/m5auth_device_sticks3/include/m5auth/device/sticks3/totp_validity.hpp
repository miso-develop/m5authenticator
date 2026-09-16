#pragma once

#include <cstdint>

namespace m5auth::device::sticks3::totp_validity {

inline constexpr std::uint64_t kPeriodSeconds = 30;

struct Snapshot {
    std::uint64_t period_index{0};
    std::uint8_t seconds_remaining{0};
};

constexpr Snapshot from_unix_seconds(std::uint64_t unix_seconds) {
    return Snapshot{
        .period_index = unix_seconds / kPeriodSeconds,
        .seconds_remaining = static_cast<std::uint8_t>(
            kPeriodSeconds - (unix_seconds % kPeriodSeconds)
        ),
    };
}

constexpr bool same_period(const Snapshot& left, const Snapshot& right) {
    return left.period_index == right.period_index;
}

}  // namespace m5auth::device::sticks3::totp_validity
