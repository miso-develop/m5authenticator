#include "m5auth/storage/storage.hpp"

namespace m5auth::storage {

Status DevSecurityBackend::production_security_status(
    ProductionSecurityStatus* status
) const {
    if (status == nullptr) return Status::kInvalidArgument;
    *status = ProductionSecurityStatus{};
    return Status::kInvalidArgument;
}

Status DevSecurityBackend::initialize_production_security() {
    return Status::kInvalidArgument;
}

Status Store::production_security_status(ProductionSecurityStatus* status) const {
    return security_backend_.production_security_status(status);
}

Status Store::initialize_production_security() {
    if (ready()) return Status::kInvalidArgument;

    // The irreversible initialization path is valid only for the first-time
    // state produced by a deliberately selected free HMAC key slot. In
    // particular, never reinterpret unsupported schema, corrupt storage, or an
    // I/O failure as permission to erase auth_nvs.
    if (initialization_status_ != Status::kProductionInitRequired) {
        return initialization_status_;
    }

    initialization_status_ = security_backend_.initialize_production_security();
    if (initialization_status_ != Status::kOk) return initialization_status_;

    // The backend has established the irreversible security boundary and erased
    // only the old development partition. Normal Store initialization owns
    // secure NVS initialization, schema creation, and encryption verification.
    initialization_status_ = Status::kNotReady;
    return initialize();
}

}  // namespace m5auth::storage
