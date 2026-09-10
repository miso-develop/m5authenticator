#pragma once

#include <functional>
#include <string>
#include <string_view>

#include "m5auth/core/metadata.hpp"
#include "m5auth/storage/storage.hpp"

namespace m5auth::provisioning {

inline constexpr char kProductionSecurityConfirmation[] =
    "INITIALIZE PRODUCTION SECURITY";

class SecuritySession {
public:
    using PhysicalConfirmation = std::function<bool()>;

    SecuritySession(
        const core::DeviceMetadata& metadata,
        storage::Store& store,
        PhysicalConfirmation physical_confirmation
    );

    std::string handle_line(std::string_view line);

private:
    const core::DeviceMetadata& metadata_;
    storage::Store& store_;
    PhysicalConfirmation physical_confirmation_;
    bool prepared_{false};
};

}  // namespace m5auth::provisioning
