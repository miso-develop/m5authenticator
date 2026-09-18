#pragma once

#include <cstdint>

namespace m5auth::device::sticks3::ui_palette {

// RGB565 presentation palette for the M5StickS3 UI.
// Text remains authoritative; color never carries security meaning alone.
inline constexpr std::uint16_t kTitleBackground = 0x0000;     // black
inline constexpr std::uint16_t kTitleText = 0x451f;           // bright blue
inline constexpr std::uint16_t kConfirmationAction = 0x07ff;  // bright cyan

}  // namespace m5auth::device::sticks3::ui_palette
