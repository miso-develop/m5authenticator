#pragma once

#include <algorithm>
#include <cstdint>
#include <limits>

namespace m5auth::device::sticks3::label_scroll {

inline void reset(
    std::uint64_t now_ms,
    std::uint64_t* epoch_ms,
    int* offset_px
) noexcept {
    if (epoch_ms == nullptr || offset_px == nullptr) return;
    *epoch_ms = now_ms;
    *offset_px = 0;
}

inline bool on_screen_hidden_changed(
    bool was_hidden,
    bool is_hidden,
    std::uint64_t now_ms,
    std::uint64_t* epoch_ms,
    int* offset_px
) noexcept {
    if (was_hidden == is_hidden) return false;
    reset(now_ms, epoch_ms, offset_px);
    return true;
}

inline bool dwell_elapsed(
    bool screen_hidden,
    std::uint64_t epoch_ms,
    std::uint64_t now_ms,
    std::uint64_t delay_ms
) noexcept {
    if (screen_hidden || now_ms < epoch_ms) return false;
    return now_ms - epoch_ms >= delay_ms;
}

inline std::uint64_t saturating_add(std::uint64_t left, std::uint64_t right) noexcept {
    return left > std::numeric_limits<std::uint64_t>::max() - right
        ? std::numeric_limits<std::uint64_t>::max()
        : left + right;
}

inline std::uint64_t saturating_multiply(
    std::uint64_t left,
    std::uint64_t right
) noexcept {
    if (left == 0 || right == 0) return 0;
    return left > std::numeric_limits<std::uint64_t>::max() / right
        ? std::numeric_limits<std::uint64_t>::max()
        : left * right;
}

inline int cycle_offset_px(
    bool screen_hidden,
    std::uint64_t epoch_ms,
    std::uint64_t now_ms,
    std::uint64_t initial_dwell_ms,
    std::uint64_t step_ms,
    int step_px,
    int max_offset_px,
    std::uint64_t end_dwell_ms
) noexcept {
    if (screen_hidden || now_ms < epoch_ms || step_ms == 0 || step_px <= 0 ||
        max_offset_px <= 0) {
        return 0;
    }

    const std::uint64_t max_offset = static_cast<std::uint64_t>(max_offset_px);
    const std::uint64_t step = static_cast<std::uint64_t>(step_px);
    const std::uint64_t max_steps = (max_offset + step - 1) / step;
    const std::uint64_t scroll_duration_ms = saturating_multiply(max_steps, step_ms);
    const std::uint64_t cycle_duration_ms = saturating_add(
        saturating_add(initial_dwell_ms, scroll_duration_ms),
        end_dwell_ms
    );

    const std::uint64_t elapsed_ms = now_ms - epoch_ms;
    const std::uint64_t phase_ms = cycle_duration_ms == 0 ||
            cycle_duration_ms == std::numeric_limits<std::uint64_t>::max()
        ? elapsed_ms
        : elapsed_ms % cycle_duration_ms;

    if (phase_ms < initial_dwell_ms) return 0;

    const std::uint64_t scroll_phase_ms = phase_ms - initial_dwell_ms;
    if (scroll_phase_ms >= scroll_duration_ms) return max_offset_px;

    const std::uint64_t completed_steps = scroll_phase_ms / step_ms;
    const std::uint64_t moved_px = std::min(
        max_offset,
        saturating_multiply(completed_steps, step)
    );
    return static_cast<int>(moved_px);
}

inline bool update_offset(
    bool screen_hidden,
    int desired_offset_px,
    int* offset_px
) noexcept {
    if (offset_px == nullptr || screen_hidden || *offset_px == desired_offset_px) {
        return false;
    }
    *offset_px = desired_offset_px;
    return true;
}

}  // namespace m5auth::device::sticks3::label_scroll
