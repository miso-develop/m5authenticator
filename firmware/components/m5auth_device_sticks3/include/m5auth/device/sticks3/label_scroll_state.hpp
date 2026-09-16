#pragma once

#include <cstdint>

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
