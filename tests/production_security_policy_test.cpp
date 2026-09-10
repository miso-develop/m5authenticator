#include <cassert>

#include "m5auth/storage/storage.hpp"

using m5auth::storage::EfuseKeyState;
using m5auth::storage::ProductionSecurityStatus;
using m5auth::storage::Status;
using m5auth::storage::production_initialization_eligible;

ProductionSecurityStatus free_key() {
    ProductionSecurityStatus status{};
    status.supported = true;
    status.hmac_key_id = 0;
    status.key_state = EfuseKeyState::kFree;
    status.unused_key_blocks = 6;
    status.burn_attempted = false;
    return status;
}

int main() {
    auto security = free_key();
    assert(production_initialization_eligible(
        Status::kProductionInitRequired,
        Status::kOk,
        security
    ));

    security.key_state = EfuseKeyState::kReusable;
    assert(!production_initialization_eligible(
        Status::kProductionInitRequired,
        Status::kOk,
        security
    ));

    security = free_key();
    security.burn_attempted = true;
    assert(!production_initialization_eligible(
        Status::kProductionInitRequired,
        Status::kOk,
        security
    ));

    security = free_key();
    assert(!production_initialization_eligible(
        Status::kUnsupportedSchema,
        Status::kOk,
        security
    ));
    assert(!production_initialization_eligible(
        Status::kCorrupt,
        Status::kOk,
        security
    ));
    assert(!production_initialization_eligible(
        Status::kIo,
        Status::kOk,
        security
    ));

    security.key_state = EfuseKeyState::kIncompatible;
    assert(!production_initialization_eligible(
        Status::kProductionInitRequired,
        Status::kEfuseStateInvalid,
        security
    ));

    security = free_key();
    security.supported = false;
    assert(!production_initialization_eligible(
        Status::kProductionInitRequired,
        Status::kOk,
        security
    ));
}
