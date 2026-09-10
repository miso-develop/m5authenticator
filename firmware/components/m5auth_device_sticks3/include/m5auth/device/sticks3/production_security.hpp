#pragma once

#include <cstdint>

#include "m5auth/storage/storage.hpp"

namespace m5auth::device::sticks3 {

void show_production_security_setup(
    const storage::ProductionSecurityStatus& security,
    storage::Status storage_status
);

// Blocks only in the dedicated pre-UI production setup mode. Returns true only
// after an explicit long-hold gesture on the physical StickS3 button.
bool confirm_production_security(std::uint32_t timeout_ms = 60'000);

}  // namespace m5auth::device::sticks3
