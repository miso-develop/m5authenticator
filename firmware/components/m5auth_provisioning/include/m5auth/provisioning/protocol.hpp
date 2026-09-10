#pragma once

#include <string>
#include <string_view>

#include "m5auth/core/metadata.hpp"

namespace m5auth::provisioning {

inline constexpr std::size_t kMaxMessageBytes = 1024;

std::string handle_line(
    std::string_view line,
    const core::DeviceMetadata& metadata
);

std::string message_too_large_response();

}  // namespace m5auth::provisioning
