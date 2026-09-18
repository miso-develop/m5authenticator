#pragma once

namespace m5auth::device::sticks3::ui_layout {

inline constexpr int kTitlePaddingTopPx = 1;
inline constexpr int kTitlePaddingBottomPx = 1;
inline constexpr int kTitlePaddingLeftPx = 1;
inline constexpr int kHeaderSeparatorHeightPx = 1;
inline constexpr int kContentLeftPx = 1;

inline constexpr int kLineAdvancePx = 20;
inline constexpr int kStatusBandHeightPx = 18;
inline constexpr int kAccountLabelHeightPx = 18;
inline constexpr int kAccountLabelOffsetPx = 60;
inline constexpr int kOtpOffsetPx = 81;
inline constexpr int kOtpBandHeightPx = 34;
inline constexpr int kHelpFirstOffsetPx = 79;
inline constexpr int kHelpSecondOffsetPx = 97;

struct FrameGeometry {
    int title_band_height;
    int separator_y;
    int content_start_y;
    int primary_line_y;
    int secondary_line_y;
    int tertiary_line_y;
    int account_label_y;
    int otp_y;
    int help_first_y;
    int help_second_y;
};

constexpr FrameGeometry frame_geometry(int title_font_height) {
    const int title_band_height =
        kTitlePaddingTopPx + title_font_height + kTitlePaddingBottomPx;
    const int content_start_y =
        title_band_height + kHeaderSeparatorHeightPx;
    return FrameGeometry{
        title_band_height,
        title_band_height,
        content_start_y,
        content_start_y,
        content_start_y + kLineAdvancePx,
        content_start_y + (2 * kLineAdvancePx),
        content_start_y + kAccountLabelOffsetPx,
        content_start_y + kOtpOffsetPx,
        content_start_y + kHelpFirstOffsetPx,
        content_start_y + kHelpSecondOffsetPx,
    };
}

constexpr int content_viewport_width(int display_width) {
    return display_width > kContentLeftPx ? display_width - kContentLeftPx : 0;
}

}  // namespace m5auth::device::sticks3::ui_layout
