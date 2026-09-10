#include "m5auth/storage/storage.hpp"

namespace m5auth::storage {

bool production_initialization_eligible(
    Status initialization_status,
    Status security_status,
    const ProductionSecurityStatus& security
) {
    return initialization_status == Status::kProductionInitRequired &&
        security_status == Status::kOk &&
        security.supported &&
        security.key_state == EfuseKeyState::kFree &&
        !security.burn_attempted;
}

}  // namespace m5auth::storage
