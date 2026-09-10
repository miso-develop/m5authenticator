#include "m5auth/provisioning/protocol.hpp"

#include <cmath>
#include <cstdlib>
#include <limits>
#include <string>

#include "cJSON.h"

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
    if (root == nullptr) {
        return serialize(nullptr);
    }
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

bool read_nonnegative_integer(cJSON* item, int* value) {
    if (!cJSON_IsNumber(item) || !std::isfinite(item->valuedouble)) {
        return false;
    }
    if (item->valuedouble < 0 || item->valuedouble > std::numeric_limits<int>::max()) {
        return false;
    }
    const int parsed = static_cast<int>(item->valuedouble);
    if (static_cast<double>(parsed) != item->valuedouble) {
        return false;
    }
    *value = parsed;
    return true;
}

std::string hello_response(int id, const core::DeviceMetadata& metadata) {
    cJSON* root = cJSON_CreateObject();
    if (root == nullptr) {
        return serialize(nullptr);
    }
    cJSON_AddNumberToObject(root, "v", core::kProtocolVersion);
    cJSON_AddNumberToObject(root, "id", id);
    cJSON_AddBoolToObject(root, "ok", true);

    cJSON* data = cJSON_AddObjectToObject(root, "data");
    if (data == nullptr) {
        cJSON_Delete(root);
        return serialize(nullptr);
    }
    cJSON_AddStringToObject(data, "device", metadata.device);
    cJSON_AddStringToObject(data, "firmware", metadata.firmware);
    cJSON_AddNumberToObject(data, "protocol", metadata.protocol);
    cJSON_AddNumberToObject(data, "storage_schema", metadata.storage_schema);
    cJSON_AddStringToObject(data, "build_commit", metadata.build_commit);
    return serialize(root);
}

}  // namespace

std::string message_too_large_response() {
    return error_response(0, "message_too_large");
}

std::string handle_line(
    std::string_view line,
    const core::DeviceMetadata& metadata
) {
    if (line.empty()) {
        return error_response(0, "invalid_request");
    }
    if (line.size() > kMaxMessageBytes) {
        return message_too_large_response();
    }

    cJSON* root = cJSON_ParseWithLength(line.data(), line.size());
    if (root == nullptr || !cJSON_IsObject(root)) {
        if (root != nullptr) {
            cJSON_Delete(root);
        }
        return error_response(0, "invalid_json");
    }

    int id = 0;
    if (!read_nonnegative_integer(cJSON_GetObjectItemCaseSensitive(root, "id"), &id)) {
        cJSON_Delete(root);
        return error_response(0, "invalid_id");
    }

    int version = 0;
    if (!read_nonnegative_integer(
            cJSON_GetObjectItemCaseSensitive(root, "v"), &version
        ) || version != core::kProtocolVersion) {
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
    cJSON_Delete(root);

    if (operation == "hello") {
        return hello_response(id, metadata);
    }
    return error_response(id, "unsupported_op");
}

}  // namespace m5auth::provisioning
