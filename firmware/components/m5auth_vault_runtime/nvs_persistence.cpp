#include "m5auth/vault_runtime/runtime.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <vector>

#include "nvs.h"
#include "nvs_flash.h"

namespace m5auth::vault_runtime {
namespace {

constexpr char kPartitionLabel[] = "auth_nvs";
constexpr char kNamespace[] = "vault2";
constexpr char kLegacyNamespace[] = "state";
constexpr char kSchemaKey[] = "schema";
constexpr char kActiveSlotKey[] = "active";
constexpr char kSlot0Key[] = "slot0";
constexpr char kSlot1Key[] = "slot1";
constexpr char kLastUsedKey[] = "last_used";
constexpr std::array<std::uint8_t, 8> kEnvelopeMagic{
    'M', '5', 'A', 'V', 'L', 'T', '2', 0};

Status map_error(esp_err_t error) {
    switch (error) {
        case ESP_OK:
            return Status::kOk;
        case ESP_ERR_NVS_NOT_FOUND:
        case ESP_ERR_NOT_FOUND:
            return Status::kNotFound;
        case ESP_ERR_INVALID_ARG:
            return Status::kInvalidArgument;
        case ESP_ERR_NVS_NO_FREE_PAGES:
            return Status::kCorrupt;
        case ESP_ERR_NVS_NEW_VERSION_FOUND:
            return Status::kUnsupportedSchema;
        default:
            return Status::kIo;
    }
}

Status ensure_partition_initialized() {
    return map_error(nvs_flash_init_partition(kPartitionLabel));
}

void append_u16(std::vector<std::uint8_t>* output, std::uint16_t value) {
    output->push_back(static_cast<std::uint8_t>(value & 0xffU));
    output->push_back(static_cast<std::uint8_t>((value >> 8U) & 0xffU));
}

void append_u32(std::vector<std::uint8_t>* output, std::uint32_t value) {
    for (unsigned shift = 0; shift < 32; shift += 8) {
        output->push_back(static_cast<std::uint8_t>((value >> shift) & 0xffU));
    }
}

void append_u64(std::vector<std::uint8_t>* output, std::uint64_t value) {
    for (unsigned shift = 0; shift < 64; shift += 8) {
        output->push_back(static_cast<std::uint8_t>((value >> shift) & 0xffU));
    }
}

class Reader final {
public:
    explicit Reader(const std::vector<std::uint8_t>& input) : input_(input) {}

    bool read_exact(std::uint8_t* output, std::size_t length) {
        if (length > input_.size() - offset_) return false;
        if (length != 0) {
            std::copy_n(input_.data() + offset_, length, output);
        }
        offset_ += length;
        return true;
    }

    bool read_u16(std::uint16_t* value) {
        std::array<std::uint8_t, 2> bytes{};
        if (value == nullptr || !read_exact(bytes.data(), bytes.size())) return false;
        *value = static_cast<std::uint16_t>(bytes[0]) |
                 (static_cast<std::uint16_t>(bytes[1]) << 8U);
        return true;
    }

    bool read_u32(std::uint32_t* value) {
        std::array<std::uint8_t, 4> bytes{};
        if (value == nullptr || !read_exact(bytes.data(), bytes.size())) return false;
        *value = static_cast<std::uint32_t>(bytes[0]) |
                 (static_cast<std::uint32_t>(bytes[1]) << 8U) |
                 (static_cast<std::uint32_t>(bytes[2]) << 16U) |
                 (static_cast<std::uint32_t>(bytes[3]) << 24U);
        return true;
    }

    bool read_u64(std::uint64_t* value) {
        std::array<std::uint8_t, 8> bytes{};
        if (value == nullptr || !read_exact(bytes.data(), bytes.size())) return false;
        std::uint64_t result = 0;
        for (unsigned index = 0; index < bytes.size(); ++index) {
            result |= static_cast<std::uint64_t>(bytes[index]) << (index * 8U);
        }
        *value = result;
        return true;
    }

    bool finished() const { return offset_ == input_.size(); }

private:
    const std::vector<std::uint8_t>& input_;
    std::size_t offset_{0};
};

bool valid_envelope(const vault::VaultEnvelope& envelope) {
    return envelope.storage_schema_version == vault::kTargetStorageSchemaVersion &&
           envelope.vault_format_version == vault::kVaultFormatVersion &&
           envelope.generation != 0 &&
           !envelope.ciphertext.empty() &&
           envelope.ciphertext.size() <= kMaxPersistedCiphertextBytes &&
           envelope.ciphertext.size() <= std::numeric_limits<std::uint32_t>::max();
}

bool same_envelope(
    const vault::VaultEnvelope& left,
    const vault::VaultEnvelope& right
) {
    return left.storage_schema_version == right.storage_schema_version &&
           left.vault_format_version == right.vault_format_version &&
           left.vault_id == right.vault_id &&
           left.generation == right.generation &&
           left.nonce == right.nonce &&
           left.ciphertext == right.ciphertext &&
           left.tag == right.tag;
}

Status encode_envelope(
    const vault::VaultEnvelope& envelope,
    std::vector<std::uint8_t>* output
) {
    if (output == nullptr || !valid_envelope(envelope)) {
        return Status::kInvalidArgument;
    }

    output->clear();
    output->reserve(
        kEnvelopeMagic.size() + 2 + 2 + envelope.vault_id.size() + 8 +
        envelope.nonce.size() + envelope.tag.size() + 4 + envelope.ciphertext.size()
    );
    output->insert(output->end(), kEnvelopeMagic.begin(), kEnvelopeMagic.end());
    append_u16(output, envelope.storage_schema_version);
    append_u16(output, envelope.vault_format_version);
    output->insert(output->end(), envelope.vault_id.begin(), envelope.vault_id.end());
    append_u64(output, envelope.generation);
    output->insert(output->end(), envelope.nonce.begin(), envelope.nonce.end());
    output->insert(output->end(), envelope.tag.begin(), envelope.tag.end());
    append_u32(output, static_cast<std::uint32_t>(envelope.ciphertext.size()));
    output->insert(
        output->end(), envelope.ciphertext.begin(), envelope.ciphertext.end());
    return Status::kOk;
}

Status decode_envelope(
    const std::vector<std::uint8_t>& encoded,
    vault::VaultEnvelope* envelope
) {
    if (envelope == nullptr || encoded.empty()) return Status::kCorrupt;

    Reader reader(encoded);
    std::array<std::uint8_t, kEnvelopeMagic.size()> magic{};
    vault::VaultEnvelope candidate;
    std::uint32_t ciphertext_size = 0;
    if (!reader.read_exact(magic.data(), magic.size()) || magic != kEnvelopeMagic ||
        !reader.read_u16(&candidate.storage_schema_version) ||
        !reader.read_u16(&candidate.vault_format_version) ||
        !reader.read_exact(candidate.vault_id.data(), candidate.vault_id.size()) ||
        !reader.read_u64(&candidate.generation) ||
        !reader.read_exact(candidate.nonce.data(), candidate.nonce.size()) ||
        !reader.read_exact(candidate.tag.data(), candidate.tag.size()) ||
        !reader.read_u32(&ciphertext_size) ||
        ciphertext_size == 0 || ciphertext_size > kMaxPersistedCiphertextBytes) {
        return Status::kCorrupt;
    }

    candidate.ciphertext.resize(ciphertext_size);
    if (!reader.read_exact(candidate.ciphertext.data(), candidate.ciphertext.size()) ||
        !reader.finished() || !valid_envelope(candidate)) {
        return Status::kCorrupt;
    }
    *envelope = std::move(candidate);
    return Status::kOk;
}

Status open_namespace(nvs_open_mode_t mode, nvs_handle_t* handle) {
    return map_error(nvs_open_from_partition(
        kPartitionLabel, kNamespace, mode, handle));
}

Status read_blob(
    nvs_handle_t handle,
    const char* key,
    std::vector<std::uint8_t>* output
) {
    if (key == nullptr || output == nullptr) return Status::kInvalidArgument;
    std::size_t size = 0;
    esp_err_t result = nvs_get_blob(handle, key, nullptr, &size);
    if (result != ESP_OK) return map_error(result);
    if (size == 0 || size > kMaxPersistedCiphertextBytes + 128) {
        return Status::kCorrupt;
    }
    output->resize(size);
    result = nvs_get_blob(handle, key, output->data(), &size);
    if (result != ESP_OK) {
        output->clear();
        return map_error(result);
    }
    output->resize(size);
    return Status::kOk;
}

Status read_active(
    nvs_handle_t handle,
    bool* has_active,
    std::uint8_t* active_slot,
    vault::VaultEnvelope* envelope
) {
    if (has_active == nullptr || active_slot == nullptr || envelope == nullptr) {
        return Status::kInvalidArgument;
    }
    *has_active = false;

    std::uint8_t slot = 0;
    const esp_err_t active_result = nvs_get_u8(handle, kActiveSlotKey, &slot);
    if (active_result == ESP_ERR_NVS_NOT_FOUND) return Status::kOk;
    if (active_result != ESP_OK) return map_error(active_result);
    if (slot > 1) return Status::kCorrupt;

    std::vector<std::uint8_t> encoded;
    const Status read_status = read_blob(
        handle, slot == 0 ? kSlot0Key : kSlot1Key, &encoded);
    if (read_status != Status::kOk) return read_status;

    const Status decode_status = decode_envelope(encoded, envelope);
    secure_zero(encoded.data(), encoded.size());
    encoded.clear();
    if (decode_status != Status::kOk) return decode_status;

    *active_slot = slot;
    *has_active = true;
    return Status::kOk;
}

Status detect_legacy_schema() {
    nvs_handle_t handle = 0;
    const esp_err_t open_result = nvs_open_from_partition(
        kPartitionLabel, kLegacyNamespace, NVS_READONLY, &handle);
    if (open_result == ESP_ERR_NVS_NOT_FOUND) return Status::kUnprovisioned;
    if (open_result != ESP_OK) return map_error(open_result);

    std::uint32_t schema = 0;
    const esp_err_t schema_result = nvs_get_u32(handle, kSchemaKey, &schema);
    nvs_close(handle);
    if (schema_result == ESP_ERR_NVS_NOT_FOUND) return Status::kUnprovisioned;
    if (schema_result != ESP_OK) return map_error(schema_result);
    if (schema == 1) return Status::kReprovisionRequired;
    if (schema > kStorageSchemaVersion) return Status::kUnsupportedSchema;
    return Status::kCorrupt;
}

}  // namespace

Status NvsPersistence::load(PersistedSnapshot* snapshot) {
    if (snapshot == nullptr) return Status::kInvalidArgument;
    *snapshot = PersistedSnapshot{};

    Status status = ensure_partition_initialized();
    if (status != Status::kOk) return status;

    nvs_handle_t handle = 0;
    status = open_namespace(NVS_READONLY, &handle);
    if (status == Status::kNotFound) return detect_legacy_schema();
    if (status != Status::kOk) return status;

    std::uint32_t schema = 0;
    const esp_err_t schema_result = nvs_get_u32(handle, kSchemaKey, &schema);
    if (schema_result != ESP_OK) {
        nvs_close(handle);
        return schema_result == ESP_ERR_NVS_NOT_FOUND
            ? Status::kCorrupt
            : map_error(schema_result);
    }
    if (schema == 1) {
        nvs_close(handle);
        return Status::kReprovisionRequired;
    }
    if (schema > kStorageSchemaVersion) {
        nvs_close(handle);
        return Status::kUnsupportedSchema;
    }
    if (schema != kStorageSchemaVersion) {
        nvs_close(handle);
        return Status::kCorrupt;
    }

    snapshot->schema_ready = true;
    std::uint8_t active_slot = 0;
    status = read_active(
        handle, &snapshot->has_vault, &active_slot, &snapshot->envelope);
    if (status != Status::kOk) {
        nvs_close(handle);
        return status;
    }

    std::size_t last_used_size = 0;
    const esp_err_t last_used_probe = nvs_get_blob(
        handle, kLastUsedKey, nullptr, &last_used_size);
    if (last_used_probe == ESP_OK) {
        if (last_used_size != vault::kCredentialIdBytes) {
            nvs_close(handle);
            return Status::kCorrupt;
        }
        CredentialId credential_id{};
        const esp_err_t last_used_result = nvs_get_blob(
            handle, kLastUsedKey, credential_id.data(), &last_used_size);
        if (last_used_result != ESP_OK) {
            nvs_close(handle);
            return map_error(last_used_result);
        }
        snapshot->last_used = credential_id;
    } else if (last_used_probe != ESP_ERR_NVS_NOT_FOUND) {
        nvs_close(handle);
        return map_error(last_used_probe);
    }

    nvs_close(handle);
    return Status::kOk;
}

Status NvsPersistence::format_schema2() {
    (void)nvs_flash_deinit_partition(kPartitionLabel);
    esp_err_t result = nvs_flash_erase_partition(kPartitionLabel);
    if (result != ESP_OK) return map_error(result);

    result = nvs_flash_init_partition(kPartitionLabel);
    if (result != ESP_OK) return map_error(result);

    nvs_handle_t handle = 0;
    Status status = open_namespace(NVS_READWRITE, &handle);
    if (status != Status::kOk) return status;

    result = nvs_set_u32(handle, kSchemaKey, kStorageSchemaVersion);
    if (result == ESP_OK) result = nvs_commit(handle);
    nvs_close(handle);
    return map_error(result);
}

Status NvsPersistence::replace_envelope(
    std::uint64_t expected_generation,
    const vault::VaultEnvelope& envelope
) {
    if (!valid_envelope(envelope)) return Status::kInvalidArgument;

    Status status = ensure_partition_initialized();
    if (status != Status::kOk) return status;

    nvs_handle_t handle = 0;
    status = open_namespace(NVS_READWRITE, &handle);
    if (status != Status::kOk) return status;

    std::uint32_t schema = 0;
    esp_err_t result = nvs_get_u32(handle, kSchemaKey, &schema);
    if (result != ESP_OK || schema != kStorageSchemaVersion) {
        nvs_close(handle);
        return result == ESP_OK ? Status::kUnsupportedSchema : map_error(result);
    }

    bool has_active = false;
    std::uint8_t active_slot = 0;
    vault::VaultEnvelope current;
    status = read_active(handle, &has_active, &active_slot, &current);
    if (status != Status::kOk) {
        nvs_close(handle);
        return status;
    }

    if (expected_generation == 0) {
        if (has_active) {
            nvs_close(handle);
            return Status::kGenerationMismatch;
        }
    } else {
        if (!has_active || current.generation != expected_generation ||
            expected_generation == std::numeric_limits<std::uint64_t>::max() ||
            envelope.generation != expected_generation + 1 ||
            envelope.vault_id != current.vault_id) {
            nvs_close(handle);
            return Status::kGenerationMismatch;
        }
    }

    const std::uint8_t inactive_slot = has_active
        ? static_cast<std::uint8_t>(1U - active_slot)
        : 0;
    const char* inactive_key = inactive_slot == 0 ? kSlot0Key : kSlot1Key;

    std::vector<std::uint8_t> encoded;
    status = encode_envelope(envelope, &encoded);
    if (status != Status::kOk) {
        nvs_close(handle);
        return status;
    }

    // Phase 1: stage and durably commit the complete candidate to the inactive slot.
    result = nvs_set_blob(handle, inactive_key, encoded.data(), encoded.size());
    if (result == ESP_OK) result = nvs_commit(handle);
    if (result != ESP_OK) {
        secure_zero(encoded.data(), encoded.size());
        encoded.clear();
        nvs_close(handle);
        return map_error(result);
    }

    // Validate the durable staged copy before changing the active pointer.
    std::vector<std::uint8_t> staged_bytes;
    status = read_blob(handle, inactive_key, &staged_bytes);
    vault::VaultEnvelope staged;
    if (status == Status::kOk) status = decode_envelope(staged_bytes, &staged);
    secure_zero(staged_bytes.data(), staged_bytes.size());
    staged_bytes.clear();
    if (status != Status::kOk || !same_envelope(staged, envelope)) {
        secure_zero(encoded.data(), encoded.size());
        encoded.clear();
        nvs_close(handle);
        return status == Status::kOk ? Status::kCorrupt : status;
    }

    // Phase 2: a second commit flips the authoritative slot. Interruption before
    // this point leaves the previous active generation authoritative.
    result = nvs_set_u8(handle, kActiveSlotKey, inactive_slot);
    if (result == ESP_OK) result = nvs_commit(handle);
    secure_zero(encoded.data(), encoded.size());
    encoded.clear();
    nvs_close(handle);
    return map_error(result);
}

Status NvsPersistence::set_last_used(
    const std::optional<CredentialId>& credential_id
) {
    Status status = ensure_partition_initialized();
    if (status != Status::kOk) return status;

    nvs_handle_t handle = 0;
    status = open_namespace(NVS_READWRITE, &handle);
    if (status != Status::kOk) return status;

    std::uint32_t schema = 0;
    esp_err_t result = nvs_get_u32(handle, kSchemaKey, &schema);
    if (result != ESP_OK || schema != kStorageSchemaVersion) {
        nvs_close(handle);
        return result == ESP_OK ? Status::kUnsupportedSchema : map_error(result);
    }

    if (credential_id.has_value()) {
        result = nvs_set_blob(
            handle,
            kLastUsedKey,
            credential_id->data(),
            credential_id->size()
        );
    } else {
        result = nvs_erase_key(handle, kLastUsedKey);
        if (result == ESP_ERR_NVS_NOT_FOUND) result = ESP_OK;
    }
    if (result == ESP_OK) result = nvs_commit(handle);
    nvs_close(handle);
    return map_error(result);
}

Status NvsPersistence::erase_all() {
    (void)nvs_flash_deinit_partition(kPartitionLabel);
    return map_error(nvs_flash_erase_partition(kPartitionLabel));
}

}  // namespace m5auth::vault_runtime
