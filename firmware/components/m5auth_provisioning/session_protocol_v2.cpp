#include "m5auth/provisioning/session_protocol_v2.hpp"

#include <algorithm>
#include <array>
#include <cmath>
#include <cstring>
#include <limits>
#include <string>
#include <vector>

#include "cJSON.h"

namespace m5auth::provisioning {
namespace {

using session::AttemptId;
using session::P256PublicKey;
using session::Vmk;
using session::protocol_v2::AttemptState;
using session::protocol_v2::BeginContext;

void secure_zero(void* data, std::size_t size) {
    volatile std::uint8_t* cursor = static_cast<volatile std::uint8_t*>(data);
    while (size-- > 0) *cursor++ = 0;
}

template <typename Container>
void wipe(Container& value) {
    if (!value.empty()) {
        secure_zero(value.data(), value.size() * sizeof(typename Container::value_type));
    }
}

bool sensitive_json_field(const char* key) {
    if (key == nullptr) return false;
    return std::strcmp(key, "brk_signature") == 0 ||
        std::strcmp(key, "web_public_key") == 0 ||
        std::strcmp(key, "nonce") == 0 ||
        std::strcmp(key, "ciphertext") == 0 ||
        std::strcmp(key, "tag") == 0;
}

void wipe_sensitive_json(cJSON* item) {
    if (item == nullptr) return;
    for (cJSON* child = item->child; child != nullptr; child = child->next) {
        if (cJSON_IsString(child) && child->valuestring != nullptr && sensitive_json_field(child->string)) {
            secure_zero(child->valuestring, std::strlen(child->valuestring));
        }
        if (cJSON_IsObject(child) || cJSON_IsArray(child)) wipe_sensitive_json(child);
    }
}

void delete_request(cJSON* root) {
    wipe_sensitive_json(root);
    cJSON_Delete(root);
}

std::string serialize(cJSON* root) {
    if (root == nullptr) {
        return R"({"v":2,"id":0,"ok":false,"error":{"code":"internal_error"}})";
    }
    char* raw = cJSON_PrintUnformatted(root);
    if (raw == nullptr) {
        cJSON_Delete(root);
        return R"({"v":2,"id":0,"ok":false,"error":{"code":"internal_error"}})";
    }
    std::string result(raw);
    cJSON_free(raw);
    cJSON_Delete(root);
    return result;
}

cJSON* response_root(int id, bool ok) {
    cJSON* root = cJSON_CreateObject();
    if (root == nullptr) return nullptr;
    cJSON_AddNumberToObject(root, "v", session::protocol_v2::kProtocolVersion);
    cJSON_AddNumberToObject(root, "id", id);
    cJSON_AddBoolToObject(root, "ok", ok);
    return root;
}

std::string error_response(int id, const char* code) {
    cJSON* root = response_root(id, false);
    if (root == nullptr) return serialize(nullptr);
    cJSON* error = cJSON_AddObjectToObject(root, "error");
    if (error == nullptr) {
        cJSON_Delete(root);
        return serialize(nullptr);
    }
    cJSON_AddStringToObject(error, "code", code);
    return serialize(root);
}

std::string empty_success(int id) {
    cJSON* root = response_root(id, true);
    if (root == nullptr) return serialize(nullptr);
    if (cJSON_AddObjectToObject(root, "data") == nullptr) {
        cJSON_Delete(root);
        return serialize(nullptr);
    }
    return serialize(root);
}

bool read_nonnegative_int(cJSON* item, int* value) {
    if (value == nullptr || !cJSON_IsNumber(item) || !std::isfinite(item->valuedouble) ||
        item->valuedouble < 0 || item->valuedouble > std::numeric_limits<int>::max()) return false;
    const int parsed = static_cast<int>(item->valuedouble);
    if (static_cast<double>(parsed) != item->valuedouble) return false;
    *value = parsed;
    return true;
}

bool read_u32_allow_zero(cJSON* item, std::uint32_t* value) {
    if (value == nullptr || !cJSON_IsNumber(item) || !std::isfinite(item->valuedouble) ||
        item->valuedouble < 0 || item->valuedouble > 4'294'967'295.0) return false;
    const auto parsed = static_cast<std::uint64_t>(item->valuedouble);
    if (static_cast<double>(parsed) != item->valuedouble) return false;
    *value = static_cast<std::uint32_t>(parsed);
    return true;
}

bool parse_u64_decimal(const char* text, std::uint64_t* value) {
    if (text == nullptr || value == nullptr || *text == '\0') return false;
    if (text[0] == '0' && text[1] != '\0') return false;
    std::uint64_t parsed = 0;
    for (const char* cursor = text; *cursor != '\0'; ++cursor) {
        if (*cursor < '0' || *cursor > '9') return false;
        const std::uint8_t digit = static_cast<std::uint8_t>(*cursor - '0');
        if (parsed > (std::numeric_limits<std::uint64_t>::max() - digit) / 10) return false;
        parsed = parsed * 10 + digit;
    }
    *value = parsed;
    return true;
}

bool read_string(cJSON* object, const char* key, std::string* value, std::size_t maximum) {
    if (value == nullptr) return false;
    cJSON* item = cJSON_GetObjectItemCaseSensitive(object, key);
    if (!cJSON_IsString(item) || item->valuestring == nullptr) return false;
    const std::size_t length = std::strlen(item->valuestring);
    if (length == 0 || length > maximum) return false;
    value->assign(item->valuestring, length);
    return true;
}

template <std::size_t N>
bool read_binary(cJSON* object, const char* key, std::array<std::uint8_t, N>* output) {
    if (output == nullptr) return false;
    cJSON* item = cJSON_GetObjectItemCaseSensitive(object, key);
    if (!cJSON_IsString(item) || item->valuestring == nullptr) return false;
    std::vector<std::uint8_t> decoded;
    if (!session::protocol_v2::base64url_decode(item->valuestring, &decoded) || decoded.size() != N) {
        wipe(decoded);
        return false;
    }
    std::copy(decoded.begin(), decoded.end(), output->begin());
    wipe(decoded);
    return true;
}

bool read_optional_signature(cJSON* object, std::vector<std::uint8_t>* output) {
    if (output == nullptr) return false;
    output->clear();
    cJSON* item = cJSON_GetObjectItemCaseSensitive(object, "brk_signature");
    if (item == nullptr) return true;
    if (!cJSON_IsString(item) || item->valuestring == nullptr ||
        !session::protocol_v2::base64url_decode(item->valuestring, output) ||
        output->size() != session::kBrkSignatureBytes) {
        wipe(*output);
        output->clear();
        return false;
    }
    return true;
}

bool same_attempt(const AttemptId& left, const AttemptId& right) {
    std::uint8_t diff = 0;
    for (std::size_t index = 0; index < left.size(); ++index) {
        diff |= static_cast<std::uint8_t>(left[index] ^ right[index]);
    }
    return diff == 0;
}

std::string begin_success(int id, const session::AttemptDescriptor& descriptor, std::uint64_t now_ms) {
    cJSON* root = response_root(id, true);
    if (root == nullptr) return serialize(nullptr);
    cJSON* data = cJSON_AddObjectToObject(root, "data");
    if (data == nullptr) {
        cJSON_Delete(root);
        return serialize(nullptr);
    }
    const std::string attempt = session::protocol_v2::base64url_encode(descriptor.attempt_id);
    const std::string challenge = session::protocol_v2::base64url_encode(descriptor.challenge);
    const std::string device_key = session::protocol_v2::base64url_encode(descriptor.device_public_key);
    cJSON_AddStringToObject(data, "attempt_id", attempt.c_str());
    cJSON_AddStringToObject(data, "challenge", challenge.c_str());
    cJSON_AddStringToObject(data, "device_public_key", device_key.c_str());
    const std::uint64_t remaining = descriptor.expires_at_ms > now_ms
        ? descriptor.expires_at_ms - now_ms
        : 0;
    cJSON_AddNumberToObject(data, "expires_in_ms", static_cast<double>(remaining));
    return serialize(root);
}

const char* state_name(AttemptState state) {
    switch (state) {
        case AttemptState::kIdle: return "cancelled";
        case AttemptState::kAwaitingAuthorization: return "awaiting_authorization";
        case AttemptState::kAwaitingPresence: return "awaiting_presence";
        case AttemptState::kConfirmed: return "confirmed";
    }
    return "cancelled";
}

std::string state_success(int id, const char* state) {
    cJSON* root = response_root(id, true);
    if (root == nullptr) return serialize(nullptr);
    cJSON* data = cJSON_AddObjectToObject(root, "data");
    if (data == nullptr) {
        cJSON_Delete(root);
        return serialize(nullptr);
    }
    cJSON_AddStringToObject(data, "state", state);
    return serialize(root);
}

bool parse_begin_context(cJSON* params, BeginContext* context) {
    if (context == nullptr) return false;
    std::string operation;
    if (!read_string(params, "operation", &operation, 32) ||
        !session::protocol_v2::parse_operation(operation, &context->operation) ||
        !read_string(params, "device_id", &context->device_id, session::protocol_v2::kMaxDeviceIdBytes) ||
        !read_binary(params, "vault_id", &context->vault_id) ||
        !read_binary(params, "registration_id", &context->registration_id) ||
        !read_u32_allow_zero(
            cJSON_GetObjectItemCaseSensitive(params, "registration_epoch"),
            &context->registration_epoch
        ) ||
        !read_binary(params, "current_brk_public_key", &context->current_brk_public_key) ||
        !read_binary(params, "proposed_brk_public_key", &context->proposed_brk_public_key)) {
        return false;
    }
    cJSON* generation = cJSON_GetObjectItemCaseSensitive(params, "expected_generation");
    return cJSON_IsString(generation) && generation->valuestring != nullptr &&
        parse_u64_decimal(generation->valuestring, &context->expected_generation);
}

}  // namespace

StagedSessionV2Handler::StagedSessionV2Handler(
    session::protocol_v2::AttemptCoordinator& coordinator,
    const SessionV2BindingSource& binding_source,
    SessionV2VmkSink& vmk_sink
) : coordinator_(coordinator), binding_source_(binding_source), vmk_sink_(vmk_sink) {}

StagedSessionV2Handler::~StagedSessionV2Handler() {
    disconnect();
}

std::string StagedSessionV2Handler::handle_line(std::string_view line, std::uint64_t now_ms) {
    if (line.empty()) return fail_closed(0, "invalid_request");
    if (line.size() > kMaxSessionV2MessageBytes) return fail_closed(0, "message_too_large");

    cJSON* root = cJSON_ParseWithLength(line.data(), line.size());
    if (root == nullptr || !cJSON_IsObject(root)) {
        if (root != nullptr) delete_request(root);
        return fail_closed(0, "invalid_json");
    }

    int id = 0;
    int version = 0;
    if (!read_nonnegative_int(cJSON_GetObjectItemCaseSensitive(root, "id"), &id)) {
        delete_request(root);
        return fail_closed(0, "invalid_id");
    }
    if (!read_nonnegative_int(cJSON_GetObjectItemCaseSensitive(root, "v"), &version) ||
        version != session::protocol_v2::kProtocolVersion) {
        delete_request(root);
        return fail_closed(id, "unsupported_version");
    }

    cJSON* op = cJSON_GetObjectItemCaseSensitive(root, "op");
    cJSON* params = cJSON_GetObjectItemCaseSensitive(root, "params");
    if (!cJSON_IsString(op) || op->valuestring == nullptr || !cJSON_IsObject(params)) {
        delete_request(root);
        return fail_closed(id, "invalid_request");
    }

    const std::string operation(op->valuestring);
    std::string response;

    if (operation == "session.begin") {
        BeginContext parsed{};
        session::AttemptDescriptor descriptor{};
        SessionV2DeviceSnapshot snapshot{};
        coordinator_.cancel();
        clear_context();
        if (!parse_begin_context(params, &parsed)) {
            response = error_response(id, "invalid_request");
        } else if (!binding_source_.snapshot(&snapshot)) {
            response = error_response(id, "invalid_state");
        } else if (!session_v2_begin_matches_snapshot(parsed, snapshot)) {
            response = error_response(id, "binding_mismatch");
        } else if (!coordinator_.begin(parsed, now_ms, &descriptor)) {
            response = error_response(id, "invalid_request");
        } else {
            context_ = parsed;
            context_active_ = true;
            response = begin_success(id, descriptor, now_ms);
        }
    } else if (operation == "session.authorize") {
        AttemptId attempt{};
        P256PublicKey web_public{};
        std::vector<std::uint8_t> signature;
        const bool parsed = read_binary(params, "attempt_id", &attempt) &&
            read_binary(params, "web_public_key", &web_public) &&
            read_optional_signature(params, &signature);
        if (!parsed) {
            response = fail_closed(id, "invalid_request");
        } else if (!context_active_ || !coordinator_.active() ||
            !same_attempt(attempt, coordinator_.descriptor().attempt_id)) {
            response = fail_closed(id, "stale_attempt");
        } else if (!current_binding_matches()) {
            response = fail_closed(id, "binding_mismatch");
        } else if (!coordinator_.authorize(web_public, signature, now_ms)) {
            clear_context();
            response = error_response(id, "authentication_failed");
        } else {
            response = empty_success(id);
        }
        wipe(signature);
        wipe(web_public);
        wipe(attempt);
    } else if (operation == "session.status") {
        AttemptId attempt{};
        if (!read_binary(params, "attempt_id", &attempt)) {
            response = fail_closed(id, "invalid_request");
        } else if (!context_active_ || !coordinator_.active() ||
            !same_attempt(attempt, coordinator_.descriptor().attempt_id)) {
            response = fail_closed(id, "stale_attempt");
        } else if (!current_binding_matches()) {
            response = fail_closed(id, "binding_mismatch");
        } else if (coordinator_.expire(now_ms)) {
            clear_context();
            response = state_success(id, "expired");
        } else {
            response = state_success(id, state_name(coordinator_.state()));
        }
        wipe(attempt);
    } else if (operation == "session.complete") {
        AttemptId attempt{};
        std::array<std::uint8_t, session::kSessionNonceBytes> nonce{};
        Vmk ciphertext{};
        std::array<std::uint8_t, session::kSessionTagBytes> tag{};
        const bool parsed = read_binary(params, "attempt_id", &attempt) &&
            read_binary(params, "nonce", &nonce) &&
            read_binary(params, "ciphertext", &ciphertext) &&
            read_binary(params, "tag", &tag);
        if (!parsed) {
            response = fail_closed(id, "invalid_request");
        } else if (!context_active_ || !coordinator_.active() ||
            !same_attempt(attempt, coordinator_.descriptor().attempt_id)) {
            response = fail_closed(id, "stale_attempt");
        } else if (!current_binding_matches()) {
            response = fail_closed(id, "binding_mismatch");
        } else {
            Vmk vmk{};
            const bool opened = coordinator_.complete(nonce, ciphertext, tag, now_ms, &vmk);
            if (!opened) {
                clear_context();
                response = error_response(id, "session_rejected");
            } else if (!current_binding_matches()) {
                wipe(vmk);
                clear_context();
                response = error_response(id, "binding_mismatch");
            } else {
                const bool installed = vmk_sink_.install_vmk(context_, vmk);
                wipe(vmk);
                clear_context();
                response = installed ? empty_success(id) : error_response(id, "invalid_state");
            }
            wipe(vmk);
        }
        wipe(tag);
        wipe(ciphertext);
        wipe(nonce);
        wipe(attempt);
    } else if (operation == "session.cancel") {
        AttemptId attempt{};
        if (!read_binary(params, "attempt_id", &attempt)) {
            response = fail_closed(id, "invalid_request");
        } else if (!context_active_ || !coordinator_.active()) {
            clear_context();
            response = empty_success(id);
        } else if (!same_attempt(attempt, coordinator_.descriptor().attempt_id)) {
            response = fail_closed(id, "stale_attempt");
        } else {
            coordinator_.cancel();
            clear_context();
            response = empty_success(id);
        }
        wipe(attempt);
    } else {
        response = fail_closed(id, "unsupported_op");
    }

    delete_request(root);
    return response;
}

bool StagedSessionV2Handler::current_binding_matches() const {
    if (!context_active_) return false;
    SessionV2DeviceSnapshot snapshot{};
    return binding_source_.snapshot(&snapshot) &&
        session_v2_begin_matches_snapshot(context_, snapshot);
}

std::string StagedSessionV2Handler::fail_closed(int id, const char* code) {
    coordinator_.cancel();
    clear_context();
    return error_response(id, code);
}

void StagedSessionV2Handler::disconnect() {
    coordinator_.disconnect();
    clear_context();
}

void StagedSessionV2Handler::clear_context() {
    if (!context_.device_id.empty()) secure_zero(context_.device_id.data(), context_.device_id.size());
    context_.device_id.clear();
    wipe(context_.vault_id);
    context_.expected_generation = 0;
    wipe(context_.registration_id);
    context_.registration_epoch = 0;
    wipe(context_.current_brk_public_key);
    wipe(context_.proposed_brk_public_key);
    context_active_ = false;
}

std::string session_v2_message_too_large_response() {
    return error_response(0, "message_too_large");
}

}  // namespace m5auth::provisioning
