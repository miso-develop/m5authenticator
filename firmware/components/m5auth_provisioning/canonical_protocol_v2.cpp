#include "m5auth/provisioning/canonical_protocol_v2.hpp"

#include <algorithm>
#include <cmath>
#include <cstring>
#include <limits>
#include <string>
#include <vector>

#include "cJSON.h"
#include "esp_random.h"

namespace m5auth::provisioning {
namespace {

void secure_zero(void* data, std::size_t size) {
    volatile auto* cursor = static_cast<volatile std::uint8_t*>(data);
    while (size-- > 0) *cursor++ = 0;
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
        if (cJSON_IsString(child) && child->valuestring != nullptr &&
            sensitive_json_field(child->string)) {
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

std::string recovery_reset_begin_success(int id, const session::AttemptId& attempt_id) {
    cJSON* root = response_root(id, true);
    if (root == nullptr) return serialize(nullptr);
    cJSON* data = cJSON_AddObjectToObject(root, "data");
    if (data == nullptr) {
        cJSON_Delete(root);
        return serialize(nullptr);
    }
    const std::string encoded = session::protocol_v2::base64url_encode(attempt_id);
    cJSON_AddStringToObject(data, "attempt_id", encoded.c_str());
    cJSON_AddNumberToObject(data, "expires_in_ms", session::kAttemptTtlMs);
    return serialize(root);
}

std::string recovery_reset_status_success(int id, bool confirmed) {
    cJSON* root = response_root(id, true);
    if (root == nullptr) return serialize(nullptr);
    cJSON* data = cJSON_AddObjectToObject(root, "data");
    if (data == nullptr) {
        cJSON_Delete(root);
        return serialize(nullptr);
    }
    cJSON_AddStringToObject(data, "state", confirmed ? "confirmed" : "awaiting_confirmation");
    return serialize(root);
}

bool read_nonnegative_int(cJSON* item, int* value) {
    if (value == nullptr || !cJSON_IsNumber(item) || !std::isfinite(item->valuedouble) ||
        item->valuedouble < 0 || item->valuedouble > std::numeric_limits<int>::max()) {
        return false;
    }
    const int parsed = static_cast<int>(item->valuedouble);
    if (static_cast<double>(parsed) != item->valuedouble) return false;
    *value = parsed;
    return true;
}

bool read_u64_decimal(cJSON* item, std::uint64_t* value) {
    if (value == nullptr || !cJSON_IsString(item) || item->valuestring == nullptr ||
        item->valuestring[0] == '\0') return false;
    const char* text = item->valuestring;
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

template <std::size_t N>
bool read_binary(cJSON* object, const char* key, std::array<std::uint8_t, N>* output) {
    if (output == nullptr) return false;
    cJSON* item = cJSON_GetObjectItemCaseSensitive(object, key);
    if (!cJSON_IsString(item) || item->valuestring == nullptr) return false;
    std::vector<std::uint8_t> decoded;
    if (!session::protocol_v2::base64url_decode(item->valuestring, &decoded) || decoded.size() != N) {
        if (!decoded.empty()) secure_zero(decoded.data(), decoded.size());
        return false;
    }
    std::copy(decoded.begin(), decoded.end(), output->begin());
    if (!decoded.empty()) secure_zero(decoded.data(), decoded.size());
    return true;
}

bool read_ciphertext(cJSON* object, std::vector<std::uint8_t>* output) {
    if (output == nullptr) return false;
    cJSON* item = cJSON_GetObjectItemCaseSensitive(object, "ciphertext");
    if (!cJSON_IsString(item) || item->valuestring == nullptr ||
        !session::protocol_v2::base64url_decode(item->valuestring, output) ||
        output->empty() || output->size() > vault_runtime::kMaxPersistedCiphertextBytes) {
        if (!output->empty()) secure_zero(output->data(), output->size());
        output->clear();
        return false;
    }
    return true;
}

bool read_envelope(cJSON* params, vault::VaultEnvelope* envelope) {
    if (params == nullptr || envelope == nullptr) return false;
    int vault_format = 0;
    int storage_schema = 0;
    int ciphertext_length = 0;
    std::uint64_t generation = 0;
    vault::VaultEnvelope parsed{};
    if (!read_nonnegative_int(cJSON_GetObjectItemCaseSensitive(params, "vault_format_version"), &vault_format) ||
        !read_nonnegative_int(cJSON_GetObjectItemCaseSensitive(params, "storage_schema_version"), &storage_schema) ||
        vault_format != vault::kVaultFormatVersion ||
        storage_schema != vault::kTargetStorageSchemaVersion ||
        !read_binary(params, "vault_id", &parsed.vault_id) ||
        !read_u64_decimal(cJSON_GetObjectItemCaseSensitive(params, "generation"), &generation) ||
        generation == 0 ||
        !read_binary(params, "nonce", &parsed.nonce) ||
        !read_binary(params, "tag", &parsed.tag) ||
        !read_ciphertext(params, &parsed.ciphertext) ||
        !read_nonnegative_int(cJSON_GetObjectItemCaseSensitive(params, "ciphertext_length"), &ciphertext_length) ||
        ciphertext_length <= 0 ||
        static_cast<std::size_t>(ciphertext_length) != parsed.ciphertext.size()) {
        if (!parsed.ciphertext.empty()) secure_zero(parsed.ciphertext.data(), parsed.ciphertext.size());
        return false;
    }
    parsed.vault_format_version = static_cast<std::uint16_t>(vault_format);
    parsed.storage_schema_version = static_cast<std::uint16_t>(storage_schema);
    parsed.generation = generation;
    *envelope = std::move(parsed);
    return true;
}

bool response_ok(const std::string& response) {
    cJSON* root = cJSON_ParseWithLength(response.data(), response.size());
    if (root == nullptr) return false;
    cJSON* ok = cJSON_GetObjectItemCaseSensitive(root, "ok");
    const bool result = cJSON_IsTrue(ok);
    cJSON_Delete(root);
    return result;
}

bool same_attempt_id(const session::AttemptId& left, const session::AttemptId& right) {
    std::uint8_t difference = 0;
    for (std::size_t index = 0; index < left.size(); ++index) {
        difference |= static_cast<std::uint8_t>(left[index] ^ right[index]);
    }
    return difference == 0;
}

bool all_zero_attempt(const session::AttemptId& value) {
    return std::all_of(value.begin(), value.end(), [](std::uint8_t byte) { return byte == 0; });
}

std::uint64_t recovery_deadline_from(std::uint64_t now_ms) {
    return now_ms > std::numeric_limits<std::uint64_t>::max() - session::kAttemptTtlMs
        ? std::numeric_limits<std::uint64_t>::max()
        : now_ms + session::kAttemptTtlMs;
}

bool destroys_runtime_vmk(session::protocol_v2::Operation operation) {
    return operation == session::protocol_v2::Operation::kRecovery ||
        operation == session::protocol_v2::Operation::kBrowserReplacement ||
        operation == session::protocol_v2::Operation::kVmkRekey;
}

const char* runtime_state_name(vault_runtime::State state) {
    switch (state) {
        case vault_runtime::State::kUnprovisioned: return "unprovisioned";
        case vault_runtime::State::kReprovisionRequired: return "reprovision_required";
        case vault_runtime::State::kLocked: return "locked";
        case vault_runtime::State::kUnlocked: return "unlocked";
        case vault_runtime::State::kError: return "error";
    }
    return "error";
}

std::string hello_success(
    int id,
    const core::DeviceMetadata& metadata,
    const vault_runtime::Metadata& runtime_metadata,
    const registration::Snapshot& registration_snapshot,
    bool recovery_reset_required
) {
    cJSON* root = response_root(id, true);
    if (root == nullptr) return serialize(nullptr);
    cJSON* data = cJSON_AddObjectToObject(root, "data");
    if (data == nullptr) {
        cJSON_Delete(root);
        return serialize(nullptr);
    }

    const std::string device_id = registration::device_id_text(registration_snapshot.device_id);
    cJSON_AddStringToObject(data, "device", metadata.device);
    cJSON_AddStringToObject(data, "device_id", device_id.c_str());
    cJSON_AddStringToObject(data, "firmware", metadata.firmware);
    cJSON_AddNumberToObject(data, "protocol", session::protocol_v2::kProtocolVersion);
    cJSON_AddNumberToObject(data, "storage_schema", vault::kTargetStorageSchemaVersion);
    cJSON_AddNumberToObject(data, "vault_format", vault::kVaultFormatVersion);
    cJSON_AddStringToObject(data, "build_commit", metadata.build_commit);
    cJSON_AddStringToObject(data, "state", runtime_state_name(runtime_metadata.state));
    cJSON_AddBoolToObject(data, "storage_ready", runtime_metadata.schema_ready);
    cJSON_AddBoolToObject(data, "recovery_reset_required", recovery_reset_required);
    cJSON_AddBoolToObject(data, "vault_present", runtime_metadata.has_vault);
    if (runtime_metadata.has_vault) {
        const std::string vault_id = session::protocol_v2::base64url_encode(runtime_metadata.vault_id);
        cJSON_AddStringToObject(data, "vault_id", vault_id.c_str());
        cJSON_AddStringToObject(data, "generation", std::to_string(runtime_metadata.generation).c_str());
    } else {
        cJSON_AddNullToObject(data, "vault_id");
        cJSON_AddStringToObject(data, "generation", "0");
    }

    cJSON_AddBoolToObject(data, "registration_present", registration_snapshot.registration_present);
    if (registration_snapshot.registration_present) {
        const std::string registration_id = session::protocol_v2::base64url_encode(registration_snapshot.registration_id);
        const std::string brk = session::protocol_v2::base64url_encode(registration_snapshot.brk_public_key);
        cJSON_AddStringToObject(data, "registration_id", registration_id.c_str());
        cJSON_AddNumberToObject(data, "registration_epoch", registration_snapshot.epoch);
        cJSON_AddStringToObject(data, "brk_public_key", brk.c_str());
    } else {
        cJSON_AddNullToObject(data, "registration_id");
        cJSON_AddNumberToObject(data, "registration_epoch", 0);
        cJSON_AddNullToObject(data, "brk_public_key");
    }
    return serialize(root);
}

std::string time_status_success(int id, const time::Snapshot& snapshot) {
    cJSON* root = response_root(id, true);
    if (root == nullptr) return serialize(nullptr);
    cJSON* data = cJSON_AddObjectToObject(root, "data");
    if (data == nullptr) {
        cJSON_Delete(root);
        return serialize(nullptr);
    }
    cJSON_AddStringToObject(data, "readiness", time::readiness_name(snapshot.readiness));
    cJSON_AddStringToObject(data, "source", time::source_name(snapshot.source));
    cJSON_AddStringToObject(data, "last_sync_unix_seconds", std::to_string(snapshot.last_sync_unix_seconds).c_str());
    cJSON_AddNumberToObject(data, "age_seconds", static_cast<double>(snapshot.age_seconds));
    cJSON_AddBoolToObject(data, "resync_due", snapshot.resync_due);
    return serialize(root);
}

bool parse_session_operation(cJSON* params, session::protocol_v2::Operation* operation) {
    if (params == nullptr || operation == nullptr) return false;
    cJSON* value = cJSON_GetObjectItemCaseSensitive(params, "operation");
    return cJSON_IsString(value) && value->valuestring != nullptr &&
        session::protocol_v2::parse_operation(value->valuestring, operation);
}

}  // namespace

CanonicalProtocolV2Handler::CanonicalProtocolV2Handler(
    const core::DeviceMetadata& metadata,
    vault_runtime::Runtime& runtime,
    registration::Store& registration,
    time::TimeService& time_service,
    StagedSessionV2Handler& session_handler,
    CanonicalVmkSink& vmk_sink,
    session::protocol_v2::PresenceBinding& recovery_presence,
    std::recursive_mutex& runtime_access_mutex
) : metadata_(metadata),
    runtime_(runtime),
    registration_(registration),
    time_service_(time_service),
    session_handler_(session_handler),
    vmk_sink_(vmk_sink),
    recovery_presence_(recovery_presence),
    runtime_access_mutex_(runtime_access_mutex) {}

CanonicalProtocolV2Handler::~CanonicalProtocolV2Handler() {
    disconnect();
}

void CanonicalProtocolV2Handler::cancel_recovery_reset() {
    if (recovery_reset_active_) recovery_presence_.cancel_presence();
    recovery_reset_attempt_id_.fill(0);
    recovery_reset_deadline_ms_ = 0;
    recovery_reset_active_ = false;
}

RecoveryResetDecision CanonicalProtocolV2Handler::recovery_reset_decision(
    vault_runtime::Metadata* runtime_metadata,
    registration::Snapshot* registration_snapshot,
    registration::Status* registration_status
) {
    if (runtime_metadata == nullptr || registration_snapshot == nullptr || registration_status == nullptr) {
        return RecoveryResetDecision::kUnavailable;
    }
    std::lock_guard<std::recursive_mutex> access(runtime_access_mutex_);
    if (runtime_.metadata(runtime_metadata) != vault_runtime::Status::kOk) {
        return RecoveryResetDecision::kUnavailable;
    }
    *registration_status = registration_.snapshot(registration_snapshot);
    return classify_recovery_reset(
        *runtime_metadata,
        *registration_status,
        *registration_snapshot,
        registration_.recovery_reset_available()
    );
}

std::string CanonicalProtocolV2Handler::handle_line(
    std::string_view line,
    std::uint64_t now_ms
) {
    housekeeping(now_ms);
    if (line.empty()) return error_response(0, "invalid_request");
    if (line.size() > kMaxCanonicalV2MessageBytes) {
        disconnect();
        return canonical_v2_message_too_large_response();
    }

    cJSON* root = cJSON_ParseWithLength(line.data(), line.size());
    if (root == nullptr || !cJSON_IsObject(root)) {
        if (root != nullptr) delete_request(root);
        disconnect();
        return error_response(0, "invalid_json");
    }

    int id = 0;
    int version = 0;
    if (!read_nonnegative_int(cJSON_GetObjectItemCaseSensitive(root, "id"), &id)) {
        delete_request(root);
        disconnect();
        return error_response(0, "invalid_id");
    }
    if (!read_nonnegative_int(cJSON_GetObjectItemCaseSensitive(root, "v"), &version) ||
        version != session::protocol_v2::kProtocolVersion) {
        delete_request(root);
        disconnect();
        return error_response(id, "unsupported_version");
    }

    cJSON* op_value = cJSON_GetObjectItemCaseSensitive(root, "op");
    cJSON* params = cJSON_GetObjectItemCaseSensitive(root, "params");
    if (!cJSON_IsString(op_value) || op_value->valuestring == nullptr || !cJSON_IsObject(params)) {
        delete_request(root);
        disconnect();
        return error_response(id, "invalid_request");
    }
    const std::string operation(op_value->valuestring);

    if (operation.rfind("session.", 0) == 0) {
        cancel_recovery_reset();
        if (line.size() > kMaxSessionV2MessageBytes) {
            delete_request(root);
            disconnect();
            return session_v2_message_too_large_response();
        }

        session::protocol_v2::Operation session_operation = session::protocol_v2::Operation::kTrustedBrowserUnlock;
        const bool begin = operation == "session.begin";
        if (begin && !parse_session_operation(params, &session_operation)) {
            delete_request(root);
            disconnect();
            return error_response(id, "invalid_request");
        }

        std::string response = session_handler_.handle_line(line, now_ms);
        if (begin && response_ok(response)) {
            session::protocol_v2::BeginContext boundary{};
            boundary.operation = session_operation;
            const auto prepare = [&]() { return vmk_sink_.prepare_attempt(boundary); };
            const bool prepared = destroys_runtime_vmk(session_operation)
                ? time_service_.with_secret_boundary(prepare)
                : prepare();
            if (!prepared) {
                session_handler_.disconnect();
                vmk_sink_.cancel_pending();
                response = error_response(id, "invalid_state");
            }
        } else if (operation == "session.complete" && response_ok(response)) {
            vmk_sink_.arm_pending_deadline(now_ms);
        } else if (operation == "session.cancel") {
            vmk_sink_.cancel_pending();
        }
        delete_request(root);
        return response;
    }

    std::string response;
    if (operation == "hello") {
        vault_runtime::Metadata runtime_metadata{};
        registration::Snapshot registration_snapshot{};
        registration::Status registration_status = registration::Status::kIo;
        const RecoveryResetDecision decision = recovery_reset_decision(
            &runtime_metadata, &registration_snapshot, &registration_status
        );
        if (decision == RecoveryResetDecision::kUnavailable) {
            response = error_response(id, "invalid_state");
        } else {
            response = hello_success(
                id,
                metadata_,
                runtime_metadata,
                registration_snapshot,
                decision == RecoveryResetDecision::kRequired
            );
        }
    } else if (operation == "factory_reset.recovery_begin") {
        vault_runtime::Metadata runtime_metadata{};
        registration::Snapshot registration_snapshot{};
        registration::Status registration_status = registration::Status::kIo;
        if (recovery_reset_decision(
                &runtime_metadata, &registration_snapshot, &registration_status
            ) != RecoveryResetDecision::kRequired) {
            response = error_response(id, "invalid_state");
        } else {
            session_handler_.disconnect();
            vmk_sink_.cancel_pending();
            cancel_recovery_reset();

            const vault_runtime::Status boundary_status = time_service_.with_secret_boundary([&]() {
                std::lock_guard<std::recursive_mutex> access(runtime_access_mutex_);
                if (runtime_metadata.state == vault_runtime::State::kError) {
                    return runtime_metadata.recovery_reset_allowed
                        ? vault_runtime::Status::kOk
                        : vault_runtime::Status::kInvalidState;
                }
                return runtime_.enter_recovery_boundary();
            });
            if (boundary_status != vault_runtime::Status::kOk) {
                response = error_response(id, "invalid_state");
            } else {
                do {
                    esp_fill_random(recovery_reset_attempt_id_.data(), recovery_reset_attempt_id_.size());
                } while (all_zero_attempt(recovery_reset_attempt_id_));
                recovery_reset_deadline_ms_ = recovery_deadline_from(now_ms);
                recovery_reset_active_ = recovery_presence_.begin_presence(
                    session::PresenceOperation::kRecovery,
                    recovery_reset_attempt_id_,
                    now_ms
                );
                if (!recovery_reset_active_) {
                    cancel_recovery_reset();
                    response = error_response(id, "invalid_state");
                } else {
                    response = recovery_reset_begin_success(id, recovery_reset_attempt_id_);
                }
            }
        }
    } else if (operation == "factory_reset.recovery_status") {
        session::AttemptId attempt_id{};
        if (!read_binary(params, "attempt_id", &attempt_id)) {
            response = error_response(id, "invalid_request");
        } else if (!recovery_reset_active_ || !same_attempt_id(attempt_id, recovery_reset_attempt_id_)) {
            response = error_response(id, "invalid_state");
        } else if (now_ms >= recovery_reset_deadline_ms_) {
            cancel_recovery_reset();
            response = error_response(id, "expired");
        } else {
            response = recovery_reset_status_success(id, recovery_presence_.presence_confirmed());
        }
        attempt_id.fill(0);
    } else if (operation == "factory_reset.recovery_complete") {
        session::AttemptId attempt_id{};
        if (!read_binary(params, "attempt_id", &attempt_id)) {
            response = error_response(id, "invalid_request");
        } else if (!recovery_reset_active_ || !same_attempt_id(attempt_id, recovery_reset_attempt_id_)) {
            response = error_response(id, "invalid_state");
        } else if (now_ms >= recovery_reset_deadline_ms_) {
            cancel_recovery_reset();
            response = error_response(id, "expired");
        } else if (!recovery_presence_.consume_presence(attempt_id, now_ms)) {
            response = error_response(id, "presence_required");
        } else {
            recovery_reset_active_ = false;
            recovery_reset_attempt_id_.fill(0);
            recovery_reset_deadline_ms_ = 0;

            vault_runtime::Metadata runtime_metadata{};
            registration::Snapshot registration_snapshot{};
            registration::Status registration_status = registration::Status::kIo;
            if (recovery_reset_decision(
                    &runtime_metadata, &registration_snapshot, &registration_status
                ) != RecoveryResetDecision::kRequired) {
                response = error_response(id, "invalid_state");
            } else {
                vault_runtime::Status vault_status = vault_runtime::Status::kIo;
                registration::Status clear_status = registration::Status::kIo;
                time_service_.with_secret_boundary([&]() {
                    std::lock_guard<std::recursive_mutex> access(runtime_access_mutex_);
                    vault_status = runtime_.factory_reset();
                    if (vault_status == vault_runtime::Status::kOk) {
                        clear_status = registration_status == registration::Status::kCorrupt
                            ? registration_.clear_corrupt_registration_for_recovery()
                            : registration_.clear_registration();
                    }
                });
                response = vault_status == vault_runtime::Status::kOk && clear_status == registration::Status::kOk
                    ? empty_success(id)
                    : error_response(id, "reset_failed");
            }
        }
        attempt_id.fill(0);
    } else if (operation == "vault.install") {
        vault::VaultEnvelope envelope{};
        if (!read_envelope(params, &envelope)) {
            vmk_sink_.cancel_pending();
            response = error_response(id, "invalid_request");
        } else {
            response = vmk_sink_.install_initial_vault(std::move(envelope), now_ms)
                ? empty_success(id)
                : error_response(id, "invalid_state");
        }
    } else if (operation == "vault.update") {
        vault::VaultEnvelope envelope{};
        std::uint64_t expected_generation = 0;
        if (!read_envelope(params, &envelope) ||
            !read_u64_decimal(cJSON_GetObjectItemCaseSensitive(params, "expected_generation"), &expected_generation)) {
            response = error_response(id, "invalid_request");
        } else {
            vault_runtime::Status status = vault_runtime::Status::kIo;
            {
                std::lock_guard<std::recursive_mutex> access(runtime_access_mutex_);
                status = runtime_.update_encrypted_vault(expected_generation, std::move(envelope));
            }
            response = status == vault_runtime::Status::kOk
                ? empty_success(id)
                : error_response(id, vault_runtime::status_code(status));
        }
    } else if (operation == "vault.rekey") {
        vault::VaultEnvelope envelope{};
        std::uint64_t expected_generation = 0;
        if (!read_envelope(params, &envelope) ||
            !read_u64_decimal(cJSON_GetObjectItemCaseSensitive(params, "expected_generation"), &expected_generation)) {
            vmk_sink_.cancel_pending();
            response = error_response(id, "invalid_request");
        } else {
            response = vmk_sink_.install_rekeyed_vault(expected_generation, std::move(envelope), now_ms)
                ? empty_success(id)
                : error_response(id, "invalid_state");
        }
    } else if (operation == "time.status") {
        response = time_status_success(id, time_service_.status());
    } else if (operation == "time.sync") {
        std::uint64_t unix_seconds = 0;
        if (!read_u64_decimal(cJSON_GetObjectItemCaseSensitive(params, "unix_seconds"), &unix_seconds)) {
            response = error_response(id, "invalid_request");
        } else {
            const time::SyncResult status = time_service_.sync_from_usb(unix_seconds);
            response = status == time::SyncResult::kOk
                ? empty_success(id)
                : error_response(id, time::sync_result_code(status));
        }
    } else if (operation == "device.lock") {
        session_handler_.disconnect();
        vmk_sink_.cancel_pending();
        cancel_recovery_reset();
        const vault_runtime::Status status = time_service_.with_secret_boundary([&]() {
            std::lock_guard<std::recursive_mutex> access(runtime_access_mutex_);
            return runtime_.lock();
        });
        response = status == vault_runtime::Status::kOk
            ? empty_success(id)
            : error_response(id, vault_runtime::status_code(status));
    } else if (operation == "factory_reset") {
        vault_runtime::Metadata runtime_metadata{};
        registration::Snapshot registration_snapshot{};
        registration::Status registration_status = registration::Status::kIo;
        const RecoveryResetDecision decision = recovery_reset_decision(
            &runtime_metadata, &registration_snapshot, &registration_status
        );
        const bool reset_allowed = decision == RecoveryResetDecision::kNotRequired &&
            runtime_metadata.state == vault_runtime::State::kUnlocked;
        if (!reset_allowed) {
            response = error_response(id, "invalid_state");
        } else {
            session_handler_.disconnect();
            vmk_sink_.cancel_pending();
            cancel_recovery_reset();

            vault_runtime::Status vault_status = vault_runtime::Status::kIo;
            registration::Status registration_clear_status = registration::Status::kIo;
            time_service_.with_secret_boundary([&]() {
                std::lock_guard<std::recursive_mutex> access(runtime_access_mutex_);
                vault_status = runtime_.factory_reset();
                registration_clear_status = vault_status == vault_runtime::Status::kOk
                    ? registration_.clear_registration()
                    : registration::Status::kIo;
            });
            response = vault_status == vault_runtime::Status::kOk &&
                    registration_clear_status == registration::Status::kOk
                ? empty_success(id)
                : error_response(id, "reset_failed");
        }
    } else {
        response = error_response(id, "unsupported_op");
    }

    delete_request(root);
    return response;
}

void CanonicalProtocolV2Handler::disconnect() {
    session_handler_.disconnect();
    vmk_sink_.cancel_pending();
    cancel_recovery_reset();
}

std::string canonical_v2_message_too_large_response() {
    return error_response(0, "message_too_large");
}

}  // namespace m5auth::provisioning
