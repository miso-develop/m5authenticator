#include "m5auth/provisioning/security_protocol.hpp"

#include <cmath>
#include <cstring>
#include <limits>
#include <string>

#include "cJSON.h"
#include "m5auth/provisioning/protocol.hpp"

namespace m5auth::provisioning {
namespace {

std::string serialize(cJSON* root) {
    if (root == nullptr) {
        return R"({"v":1,"id":0,"ok":false,"error":{"code":"internal_error"}})";
    }
    char* raw = cJSON_PrintUnformatted(root);
    if (raw == nullptr) {
        cJSON_Delete(root);
        return R"({"v":1,"id":0,"ok":false,"error":{"code":"internal_error"}})";
    }
    std::string result(raw);
    cJSON_free(raw);
    cJSON_Delete(root);
    return result;
}

std::string error_response(int id, const char* code) {
    cJSON* root = cJSON_CreateObject();
    if (root == nullptr) return serialize(nullptr);
    cJSON_AddNumberToObject(root, "v", core::kProtocolVersion);
    cJSON_AddNumberToObject(root, "id", id);
    cJSON_AddBoolToObject(root, "ok", false);
    cJSON* error = cJSON_AddObjectToObject(root, "error");
    if (error == nullptr) {
        cJSON_Delete(root);
        return serialize(nullptr);
    }
    cJSON_AddStringToObject(error, "code", code);
    return serialize(root);
}

cJSON* success_root(int id) {
    cJSON* root = cJSON_CreateObject();
    if (root == nullptr) return nullptr;
    cJSON_AddNumberToObject(root, "v", core::kProtocolVersion);
    cJSON_AddNumberToObject(root, "id", id);
    cJSON_AddBoolToObject(root, "ok", true);
    return root;
}

bool read_nonnegative_integer(cJSON* item, int* value) {
    if (value == nullptr || !cJSON_IsNumber(item) || !std::isfinite(item->valuedouble)) return false;
    if (item->valuedouble < 0 || item->valuedouble > std::numeric_limits<int>::max()) return false;
    const int parsed = static_cast<int>(item->valuedouble);
    if (static_cast<double>(parsed) != item->valuedouble) return false;
    *value = parsed;
    return true;
}

const char* security_status_code(storage::Status status) {
    switch (status) {
        case storage::Status::kProductionInitRequired: return "production_init_required";
        case storage::Status::kEfuseStateInvalid: return "efuse_state_invalid";
        case storage::Status::kIrreversibleOperationFailed: return "irreversible_operation_failed";
        default: return storage::status_code(status);
    }
}

void add_security_status(cJSON* data, storage::Store& store, bool prepared) {
    storage::ProductionSecurityStatus security{};
    const storage::Status status = store.production_security_status(&security);
    cJSON_AddStringToObject(data, "security_profile", std::string(store.security_profile()).c_str());
    cJSON_AddBoolToObject(data, "supported", security.supported);
    cJSON_AddNumberToObject(data, "hmac_key_id", security.hmac_key_id);
    cJSON_AddStringToObject(data, "key_state", storage::efuse_key_state_name(security.key_state));
    cJSON_AddBoolToObject(data, "read_protected", security.read_protected);
    cJSON_AddBoolToObject(data, "write_protected", security.write_protected);
    cJSON_AddBoolToObject(data, "purpose_write_protected", security.purpose_write_protected);
    cJSON_AddNumberToObject(data, "unused_key_blocks", security.unused_key_blocks);
    cJSON_AddBoolToObject(data, "burn_attempted", security.burn_attempted);
    cJSON_AddBoolToObject(data, "prepared", prepared);
    cJSON_AddBoolToObject(data, "storage_ready", store.ready());
    cJSON_AddStringToObject(data, "storage_status", security_status_code(store.initialization_status()));
    cJSON_AddBoolToObject(
        data,
        "preflight_ok",
        storage::production_initialization_eligible(
            store.initialization_status(),
            status,
            security
        )
    );
}

std::string security_status_response(int id, storage::Store& store, bool prepared) {
    cJSON* root = success_root(id);
    if (root == nullptr) return serialize(nullptr);
    cJSON* data = cJSON_AddObjectToObject(root, "data");
    if (data == nullptr) { cJSON_Delete(root); return serialize(nullptr); }
    add_security_status(data, store, prepared);
    return serialize(root);
}

std::string hello_response(int id, const core::DeviceMetadata& metadata, storage::Store& store) {
    cJSON* root = success_root(id);
    if (root == nullptr) return serialize(nullptr);
    cJSON* data = cJSON_AddObjectToObject(root, "data");
    if (data == nullptr) { cJSON_Delete(root); return serialize(nullptr); }
    cJSON_AddStringToObject(data, "device", metadata.device);
    cJSON_AddStringToObject(data, "firmware", metadata.firmware);
    cJSON_AddNumberToObject(data, "protocol", metadata.protocol);
    cJSON_AddNumberToObject(data, "storage_schema", metadata.storage_schema);
    cJSON_AddStringToObject(data, "build_commit", metadata.build_commit);
    cJSON_AddStringToObject(data, "security_profile", std::string(store.security_profile()).c_str());
    cJSON_AddBoolToObject(data, "storage_ready", store.ready());
    cJSON_AddBoolToObject(data, "production_release_allowed", store.production_release_allowed());
    cJSON_AddStringToObject(data, "storage_status", security_status_code(store.initialization_status()));
    cJSON_AddStringToObject(data, "time_state", "not_synced");
    cJSON_AddStringToObject(data, "time_source", "none");
    cJSON_AddNullToObject(data, "last_sync");
    cJSON_AddNullToObject(data, "time_age_seconds");
    cJSON_AddBoolToObject(data, "time_resync_due", false);
    return serialize(root);
}

}  // namespace

SecuritySession::SecuritySession(
    const core::DeviceMetadata& metadata,
    storage::Store& store,
    PhysicalConfirmation physical_confirmation
) : metadata_(metadata), store_(store), physical_confirmation_(std::move(physical_confirmation)) {}

std::string SecuritySession::handle_line(std::string_view line) {
    if (line.empty()) return error_response(0, "invalid_request");
    if (line.size() > kMaxMessageBytes) return message_too_large_response();

    cJSON* root = cJSON_ParseWithLength(line.data(), line.size());
    if (root == nullptr || !cJSON_IsObject(root)) {
        if (root != nullptr) cJSON_Delete(root);
        return error_response(0, "invalid_json");
    }

    int id = 0;
    int version = 0;
    if (!read_nonnegative_integer(cJSON_GetObjectItemCaseSensitive(root, "id"), &id)) {
        cJSON_Delete(root);
        return error_response(0, "invalid_id");
    }
    if (!read_nonnegative_integer(cJSON_GetObjectItemCaseSensitive(root, "v"), &version) ||
        version != core::kProtocolVersion) {
        cJSON_Delete(root);
        return error_response(id, "unsupported_version");
    }

    cJSON* op = cJSON_GetObjectItemCaseSensitive(root, "op");
    cJSON* params = cJSON_GetObjectItemCaseSensitive(root, "params");
    if (!cJSON_IsString(op) || op->valuestring == nullptr || !cJSON_IsObject(params)) {
        cJSON_Delete(root);
        return error_response(id, "invalid_request");
    }

    const std::string operation(op->valuestring);
    std::string response;
    if (operation == "hello") {
        response = hello_response(id, metadata_, store_);
    } else if (operation == "security.status") {
        response = security_status_response(id, store_, prepared_);
    } else if (operation == "security.prepare") {
        storage::ProductionSecurityStatus security{};
        const storage::Status status = store_.production_security_status(&security);
        if (store_.ready()) {
            response = error_response(id, "security_already_initialized");
        } else if (!storage::production_initialization_eligible(
                       store_.initialization_status(), status, security)) {
            // Preserve the actual storage failure. A reusable HMAC key with an
            // unsupported schema/corrupt auth_nvs is not a provisioning state and
            // must never be converted into an erase-and-reinitialize operation.
            const storage::Status blocking_status =
                store_.initialization_status() != storage::Status::kProductionInitRequired
                    ? store_.initialization_status()
                    : status;
            response = error_response(id, security_status_code(blocking_status));
        } else {
            prepared_ = true;
            response = security_status_response(id, store_, prepared_);
        }
    } else if (operation == "security.cancel") {
        prepared_ = false;
        response = security_status_response(id, store_, prepared_);
    } else if (operation == "security.commit") {
        cJSON* confirmation = cJSON_GetObjectItemCaseSensitive(params, "confirmation");
        if (!prepared_) {
            response = error_response(id, "security_init_not_prepared");
        } else if (!cJSON_IsString(confirmation) || confirmation->valuestring == nullptr ||
                   std::strcmp(confirmation->valuestring, kProductionSecurityConfirmation) != 0) {
            response = error_response(id, "web_confirmation_required");
        } else if (!physical_confirmation_ || !physical_confirmation_()) {
            prepared_ = false;
            response = error_response(id, "device_confirmation_required");
        } else {
            // Consume preparation before crossing the irreversible boundary.
            // An eFuse-related failure cannot be retried automatically in this session.
            prepared_ = false;
            const storage::Status status = store_.initialize_production_security();
            response = status == storage::Status::kOk
                ? security_status_response(id, store_, prepared_)
                : error_response(id, security_status_code(status));
        }
    } else {
        response = error_response(id, "production_security_setup_required");
    }

    cJSON_Delete(root);
    return response;
}

}  // namespace m5auth::provisioning
