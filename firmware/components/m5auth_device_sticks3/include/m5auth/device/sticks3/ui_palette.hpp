#pragma once

#include <cstdint>

namespace m5auth::device::sticks3::ui_palette {

// RGB565 accents for the M5StickS3 black-background UI.
// Keep these presentation-only: text remains the authoritative cue.
inline constexpr std::uint16_t kProductTitle = 0x1c9f;       // bright blue
inline constexpr std::uint16_t kConfirmationAction = 0x07ff; // bright cyan

}  // namespace m5auth::device::sticks3::ui_palette
