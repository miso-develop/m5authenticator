#include "m5auth/provisioning/protocol.hpp"

#include <cmath>
#include <cstring>
#include <limits>
#include <string>
#include <vector>

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

std::string storage_error_response(int id, storage::Status status) {
    return error_response(id, storage::status_code(status));
}

cJSON* success_root(int id) {
    cJSON* root = cJSON_CreateObject();
    if (root == nullptr) {
        return nullptr;
    }
    cJSON_AddNumberToObject(root, "v", core::kProtocolVersion);
    cJSON_AddNumberToObject(root, "id", id);
    cJSON_AddBoolToObject(root, "ok", true);
    return root;
}

std::string empty_success(int id) {
    cJSON* root = success_root(id);
    if (root == nullptr) {
        return serialize(nullptr);
    }
    if (cJSON_AddObjectToObject(root, "data") == nullptr) {
        cJSON_Delete(root);
        return serialize(nullptr);
    }
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

bool read_u32(cJSON* item, std::uint32_t* value) {
    int parsed = 0;
    if (!read_nonnegative_integer(item, &parsed) || parsed == 0 || value == nullptr) {
        return false;
    }
    *value = static_cast<std::uint32_t>(parsed);
    return true;
}

bool read_string(cJSON* object, const char* key, std::string* value) {
    cJSON* item = cJSON_GetObjectItemCaseSensitive(object, key);
    if (!cJSON_IsString(item) || item->valuestring == nullptr || value == nullptr) {
        return false;
    }
    value->assign(item->valuestring);
    return true;
}

void wipe_json_string(cJSON* object, const char* key) {
    cJSON* item = cJSON_GetObjectItemCaseSensitive(object, key);
    if (!cJSON_IsString(item) || item->valuestring == nullptr) {
        return;
    }
    volatile char* cursor = item->valuestring;
    while (*cursor != '\0') {
        *cursor++ = '\0';
    }
}

void wipe_sensitive_json(cJSON* item) {
    if (item == nullptr) {
        return;
    }
    for (cJSON* child = item->child; child != nullptr; child = child->next) {
        if (child->string != nullptr && cJSON_IsString(child) && child->valuestring != nullptr &&
            (std::strcmp(child->string, "secret") == 0 ||
             std::strcmp(child->string, "password") == 0)) {
            volatile char* cursor = child->valuestring;
            while (*cursor != '\0') {
                *cursor++ = '\0';
            }
        }
        if (cJSON_IsObject(child) || cJSON_IsArray(child)) {
            wipe_sensitive_json(child);
        }
    }
}

void delete_request(cJSON* root) {
    wipe_sensitive_json(root);
    cJSON_Delete(root);
}

std::string hello_response(
    int id,
    const core::DeviceMetadata& metadata,
    const storage::Store& store
) {
    cJSON* root = success_root(id);
    if (root == nullptr) {
        return serialize(nullptr);
    }
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
    const std::string profile(store.security_profile());
    cJSON_AddStringToObject(data, "security_profile", profile.c_str());
    cJSON_AddBoolToObject(data, "storage_ready", store.ready());
    cJSON_AddBoolToObject(
        data,
        "production_release_allowed",
        store.production_release_allowed()
    );
    if (!store.ready()) {
        cJSON_AddStringToObject(
            data,
            "storage_status",
            storage::status_code(store.initialization_status())
        );
    }
    return serialize(root);
}

std::string accounts_list_response(int id, storage::Store& store) {
    std::vector<storage::AccountMetadata> accounts;
    const storage::Status status = store.list_accounts(&accounts);
    if (status != storage::Status::kOk) {
        return storage_error_response(id, status);
    }

    cJSON* root = success_root(id);
    if (root == nullptr) {
        return serialize(nullptr);
    }
    cJSON* data = cJSON_AddObjectToObject(root, "data");
    cJSON* array = data == nullptr ? nullptr : cJSON_AddArrayToObject(data, "accounts");
    if (data == nullptr || array == nullptr) {
        cJSON_Delete(root);
        return serialize(nullptr);
    }
    cJSON_AddNumberToObject(data, "count", accounts.size());

    for (const auto& account : accounts) {
        cJSON* item = cJSON_CreateObject();
        if (item == nullptr) {
            cJSON_Delete(root);
            return serialize(nullptr);
        }
        cJSON_AddNumberToObject(item, "id", account.id);
        cJSON_AddNumberToObject(item, "order", account.order);
        cJSON_AddStringToObject(item, "issuer", account.issuer.c_str());
        cJSON_AddStringToObject(item, "account", account.account.c_str());
        cJSON_AddStringToObject(item, "display_name", account.display_name.c_str());
        cJSON_AddItemToArray(array, item);
    }
    return serialize(root);
}

std::string import_begin_response(int id) {
    cJSON* root = success_root(id);
    if (root == nullptr) {
        return serialize(nullptr);
    }
    cJSON* data = cJSON_AddObjectToObject(root, "data");
    if (data == nullptr) {
        cJSON_Delete(root);
        return serialize(nullptr);
    }
    cJSON_AddNumberToObject(data, "max_accounts", storage::kMaxAccounts);
    return serialize(root);
}

std::string count_success(int id, std::size_t count) {
    cJSON* root = success_root(id);
    if (root == nullptr) {
        return serialize(nullptr);
    }
    cJSON* data = cJSON_AddObjectToObject(root, "data");
    if (data == nullptr) {
        cJSON_Delete(root);
        return serialize(nullptr);
    }
    cJSON_AddNumberToObject(data, "count", count);
    return serialize(root);
}

std::string selection_response(int id, std::uint32_t selected_id) {
    cJSON* root = success_root(id);
    if (root == nullptr) {
        return serialize(nullptr);
    }
    cJSON* data = cJSON_AddObjectToObject(root, "data");
    if (data == nullptr) {
        cJSON_Delete(root);
        return serialize(nullptr);
    }
    if (selected_id == 0) {
        cJSON_AddNullToObject(data, "id");
    } else {
        cJSON_AddNumberToObject(data, "id", selected_id);
    }
    return serialize(root);
}

std::string wifi_status_response(int id, storage::Store& store) {
    storage::WifiStatus wifi{};
    const storage::Status status = store.wifi_status(&wifi);
    if (status != storage::Status::kOk) {
        return storage_error_response(id, status);
    }

    cJSON* root = success_root(id);
    if (root == nullptr) {
        return serialize(nullptr);
    }
    cJSON* data = cJSON_AddObjectToObject(root, "data");
    if (data == nullptr) {
        cJSON_Delete(root);
        return serialize(nullptr);
    }
    cJSON_AddBoolToObject(data, "configured", wifi.configured);
    cJSON_AddStringToObject(data, "ssid", wifi.ssid.c_str());
    return serialize(root);
}

}  // namespace

Session::Session(const core::DeviceMetadata& metadata, storage::Store& store)
    : metadata_(metadata), store_(store) {}

Session::~Session() {
    clear_import();
}

void Session::clear_import() {
    for (auto& account : import_accounts_) {
        storage::secure_clear(&account.secret);
    }
    import_accounts_.clear();
    import_active_ = false;
    import_validated_ = false;
}

std::string Session::handle_line(std::string_view line) {
    if (line.empty()) {
        return error_response(0, "invalid_request");
    }
    if (line.size() > kMaxMessageBytes) {
        return message_too_large_response();
    }

    cJSON* root = cJSON_ParseWithLength(line.data(), line.size());
    if (root == nullptr || !cJSON_IsObject(root)) {
        if (root != nullptr) {
            delete_request(root);
        }
        return error_response(0, "invalid_json");
    }

    int id = 0;
    if (!read_nonnegative_integer(cJSON_GetObjectItemCaseSensitive(root, "id"), &id)) {
        delete_request(root);
        return error_response(0, "invalid_id");
    }

    int version = 0;
    if (!read_nonnegative_integer(
            cJSON_GetObjectItemCaseSensitive(root, "v"), &version
        ) || version != core::kProtocolVersion) {
        delete_request(root);
        return error_response(id, "unsupported_version");
    }

    cJSON* op = cJSON_GetObjectItemCaseSensitive(root, "op");
    cJSON* params = cJSON_GetObjectItemCaseSensitive(root, "params");
    if (!cJSON_IsString(op) || op->valuestring == nullptr || !cJSON_IsObject(params)) {
        delete_request(root);
        return error_response(id, "invalid_request");
    }

    const std::string operation(op->valuestring);
    std::string response;

    if (operation == "hello") {
        response = hello_response(id, metadata_, store_);
    } else if (operation == "accounts.list") {
        response = accounts_list_response(id, store_);
    } else if (operation == "import.begin") {
        clear_import();
        import_active_ = true;
        response = import_begin_response(id);
    } else if (operation == "import.item") {
        storage::AccountDraft draft;
        const bool parsed = import_active_ &&
            read_string(params, "issuer", &draft.issuer) &&
            read_string(params, "account", &draft.account) &&
            read_string(params, "display_name", &draft.display_name) &&
            read_string(params, "secret", &draft.secret);
        wipe_json_string(params, "secret");

        if (!parsed) {
            storage::secure_clear(&draft.secret);
            response = error_response(id, "invalid_import_item");
        } else if (import_accounts_.size() >= storage::kMaxAccounts) {
            storage::secure_clear(&draft.secret);
            response = error_response(id, "storage_full");
        } else {
            const storage::Status status = storage::validate_account_draft(draft);
            if (status != storage::Status::kOk) {
                storage::secure_clear(&draft.secret);
                response = storage_error_response(id, status);
            } else {
                import_accounts_.push_back(std::move(draft));
                import_validated_ = false;
                response = count_success(id, import_accounts_.size());
            }
        }
    } else if (operation == "import.validate") {
        if (!import_active_) {
            response = error_response(id, "import_not_active");
        } else {
            storage::Status status = storage::Status::kOk;
            for (const auto& account : import_accounts_) {
                status = storage::validate_account_draft(account);
                if (status != storage::Status::kOk) {
                    break;
                }
            }
            if (status != storage::Status::kOk) {
                response = storage_error_response(id, status);
            } else {
                import_validated_ = true;
                response = count_success(id, import_accounts_.size());
            }
        }
    } else if (operation == "import.commit") {
        if (!import_active_ || !import_validated_) {
            response = error_response(id, "import_not_validated");
        } else {
            const storage::Status status = store_.replace_accounts(import_accounts_);
            clear_import();
            response = status == storage::Status::kOk
                ? empty_success(id)
                : storage_error_response(id, status);
        }
    } else if (operation == "import.cancel") {
        clear_import();
        response = empty_success(id);
    } else if (operation == "account.rename") {
        std::uint32_t account_id = 0;
        std::string display_name;
        if (!read_u32(cJSON_GetObjectItemCaseSensitive(params, "id"), &account_id) ||
            !read_string(params, "display_name", &display_name)) {
            response = error_response(id, "invalid_request");
        } else {
            const storage::Status status = store_.rename_account(account_id, display_name);
            response = status == storage::Status::kOk
                ? empty_success(id)
                : storage_error_response(id, status);
        }
    } else if (operation == "account.delete") {
        std::uint32_t account_id = 0;
        if (!read_u32(cJSON_GetObjectItemCaseSensitive(params, "id"), &account_id)) {
            response = error_response(id, "invalid_request");
        } else {
            const storage::Status status = store_.delete_account(account_id);
            response = status == storage::Status::kOk
                ? empty_success(id)
                : storage_error_response(id, status);
        }
    } else if (operation == "accounts.reorder") {
        cJSON* ids = cJSON_GetObjectItemCaseSensitive(params, "ids");
        const int count = cJSON_IsArray(ids) ? cJSON_GetArraySize(ids) : -1;
        if (count < 0 || static_cast<std::size_t>(count) > storage::kMaxAccounts) {
            response = error_response(id, "invalid_request");
        } else {
            std::vector<std::uint32_t> order;
            bool valid = true;
            cJSON* item = nullptr;
            cJSON_ArrayForEach(item, ids) {
                std::uint32_t account_id = 0;
                if (!read_u32(item, &account_id)) {
                    valid = false;
                    break;
                }
                order.push_back(account_id);
            }
            if (!valid) {
                response = error_response(id, "invalid_request");
            } else {
                const storage::Status status = store_.reorder_accounts(order);
                response = status == storage::Status::kOk
                    ? empty_success(id)
                    : storage_error_response(id, status);
            }
        }
    } else if (operation == "selection.get") {
        std::uint32_t selected = 0;
        const storage::Status status = store_.get_last_used(&selected);
        response = status == storage::Status::kOk
            ? selection_response(id, selected)
            : storage_error_response(id, status);
    } else if (operation == "selection.set") {
        std::uint32_t selected = 0;
        if (!read_u32(cJSON_GetObjectItemCaseSensitive(params, "id"), &selected)) {
            response = error_response(id, "invalid_request");
        } else {
            const storage::Status status = store_.set_last_used(selected);
            response = status == storage::Status::kOk
                ? empty_success(id)
                : storage_error_response(id, status);
        }
    } else if (operation == "wifi.status") {
        response = wifi_status_response(id, store_);
    } else if (operation == "wifi.set") {
        std::string ssid;
        std::string password;
        const bool parsed = read_string(params, "ssid", &ssid) &&
            read_string(params, "password", &password);
        wipe_json_string(params, "password");
        if (!parsed) {
            storage::secure_clear(&password);
            response = error_response(id, "invalid_request");
        } else {
            const storage::Status status = store_.set_wifi(ssid, password);
            storage::secure_clear(&password);
            response = status == storage::Status::kOk
                ? empty_success(id)
                : storage_error_response(id, status);
        }
    } else if (operation == "wifi.clear") {
        const storage::Status status = store_.clear_wifi();
        response = status == storage::Status::kOk
            ? empty_success(id)
            : storage_error_response(id, status);
    } else {
        response = error_response(id, "unsupported_op");
    }

    delete_request(root);
    return response;
}

std::string message_too_large_response() {
    return error_response(0, "message_too_large");
}

}  // namespace m5auth::provisioning
