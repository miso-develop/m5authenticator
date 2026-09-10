#include "m5auth/storage/storage.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>

#include "bootloader_random.h"
#include "esp_efuse.h"
#include "esp_partition.h"
#include "esp_random.h"
#include "nvs.h"
#include "nvs_flash.h"
#include "nvs_sec_provider.h"

namespace m5auth::storage {
namespace {

constexpr char kProbeNamespace[] = "prod_probe";
constexpr char kProbeKey[] = "probe";
constexpr std::array<std::uint8_t, 29> kProbeValue{
    'M', '5', 'A', 'U', 'T', 'H', '-', 'P', 'R', 'O', 'D', '-', 'E', 'N', 'C', '-',
    'P', 'R', 'O', 'B', 'E', '-', 'V', '1', '-', 'S', 'A', 'F', 'E'};

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
            return Status::kFull;
        case ESP_ERR_NVS_NEW_VERSION_FOUND:
            return Status::kUnsupportedSchema;
        case ESP_ERR_NVS_SEC_HMAC_KEY_NOT_FOUND:
            return Status::kProductionInitRequired;
        case ESP_ERR_NVS_SEC_HMAC_KEY_BLK_ALREADY_USED:
            return Status::kEfuseStateInvalid;
        default:
            return Status::kIo;
    }
}

bool valid_key_id(std::uint8_t key_id) {
    return key_id <= 5;
}

esp_efuse_block_t efuse_block_for(std::uint8_t key_id) {
    switch (key_id) {
        case 0: return EFUSE_BLK_KEY0;
        case 1: return EFUSE_BLK_KEY1;
        case 2: return EFUSE_BLK_KEY2;
        case 3: return EFUSE_BLK_KEY3;
        case 4: return EFUSE_BLK_KEY4;
        case 5: return EFUSE_BLK_KEY5;
        default: return EFUSE_BLK_KEY_MAX;
    }
}

hmac_key_id_t hmac_id_for(std::uint8_t key_id) {
    switch (key_id) {
        case 0: return HMAC_KEY0;
        case 1: return HMAC_KEY1;
        case 2: return HMAC_KEY2;
        case 3: return HMAC_KEY3;
        case 4: return HMAC_KEY4;
        case 5: return HMAC_KEY5;
        default: return HMAC_KEY_MAX;
    }
}

ProductionSecurityStatus inspect(std::uint8_t key_id, bool burn_attempted) {
    ProductionSecurityStatus status{};
    status.supported = valid_key_id(key_id);
    status.hmac_key_id = key_id;
    status.unused_key_blocks = esp_efuse_count_unused_key_blocks();
    status.burn_attempted = burn_attempted;
    if (!status.supported) {
        status.key_state = EfuseKeyState::kIncompatible;
        return status;
    }

    const esp_efuse_block_t block = efuse_block_for(key_id);
    status.read_protected = esp_efuse_get_key_dis_read(block);
    status.write_protected = esp_efuse_get_key_dis_write(block);
    status.purpose_write_protected = esp_efuse_get_keypurpose_dis_write(block);

    if (esp_efuse_key_block_unused(block)) {
        status.key_state = EfuseKeyState::kFree;
        return status;
    }

    const bool correct_purpose =
        esp_efuse_get_key_purpose(block) == ESP_EFUSE_KEY_PURPOSE_HMAC_UP;
    status.key_state = correct_purpose && status.read_protected &&
            status.write_protected && status.purpose_write_protected
        ? EfuseKeyState::kReusable
        : EfuseKeyState::kIncompatible;
    return status;
}

Status derive_and_initialize(std::uint8_t key_id) {
    if (!valid_key_id(key_id)) return Status::kInvalidArgument;

    nvs_sec_config_hmac_t scheme_config{};
    scheme_config.hmac_key_id = hmac_id_for(key_id);
    nvs_sec_scheme_t* scheme = nullptr;
    esp_err_t result = nvs_sec_provider_register_hmac(&scheme_config, &scheme);
    if (result != ESP_OK) return map_error(result);

    nvs_sec_cfg_t config{};
    result = nvs_flash_read_security_cfg_v2(scheme, &config);
    const esp_err_t deregister_result = nvs_sec_provider_deregister(scheme);
    if (result != ESP_OK) {
        secure_zero(&config, sizeof(config));
        return map_error(result);
    }
    if (deregister_result != ESP_OK) {
        secure_zero(&config, sizeof(config));
        return map_error(deregister_result);
    }

    result = nvs_flash_secure_init_partition(kPartitionLabel, &config);
    secure_zero(&config, sizeof(config));
    return map_error(result);
}

Status verify_probe_not_plaintext() {
    nvs_handle_t handle = 0;
    esp_err_t result = nvs_open_from_partition(
        kPartitionLabel,
        kProbeNamespace,
        NVS_READWRITE,
        &handle
    );
    if (result != ESP_OK) return map_error(result);

    result = nvs_set_blob(handle, kProbeKey, kProbeValue.data(), kProbeValue.size());
    if (result == ESP_OK) result = nvs_commit(handle);
    nvs_close(handle);
    if (result != ESP_OK) return map_error(result);

    const esp_partition_t* partition = esp_partition_find_first(
        ESP_PARTITION_TYPE_DATA,
        ESP_PARTITION_SUBTYPE_DATA_NVS,
        kPartitionLabel
    );
    if (partition == nullptr) return Status::kNotFound;

    constexpr std::size_t kChunkSize = 256;
    std::array<std::uint8_t, kChunkSize + kProbeValue.size() - 1> buffer{};
    std::size_t carry = 0;
    std::size_t offset = 0;
    bool plaintext_found = false;
    Status scan_status = Status::kOk;

    while (offset < partition->size && !plaintext_found) {
        const std::size_t chunk = std::min(
            kChunkSize,
            static_cast<std::size_t>(partition->size - offset)
        );
        result = esp_partition_read(partition, offset, buffer.data() + carry, chunk);
        if (result != ESP_OK) {
            scan_status = map_error(result);
            break;
        }
        const std::size_t available = carry + chunk;
        const auto end = buffer.begin() + static_cast<std::ptrdiff_t>(available);
        plaintext_found = std::search(
            buffer.begin(), end, kProbeValue.begin(), kProbeValue.end()
        ) != end;
        carry = std::min(kProbeValue.size() - 1, available);
        if (carry > 0) {
            std::memmove(buffer.data(), buffer.data() + available - carry, carry);
        }
        offset += chunk;
    }
    secure_zero(buffer.data(), buffer.size());

    handle = 0;
    result = nvs_open_from_partition(kPartitionLabel, kProbeNamespace, NVS_READWRITE, &handle);
    if (result == ESP_OK) {
        result = nvs_erase_key(handle, kProbeKey);
        if (result == ESP_ERR_NVS_NOT_FOUND) result = ESP_OK;
        if (result == ESP_OK) result = nvs_commit(handle);
        nvs_close(handle);
    }

    if (scan_status != Status::kOk) return scan_status;
    if (plaintext_found) return Status::kSecurityInvariant;
    return map_error(result);
}

Status burn_hmac_key_atomically(std::uint8_t key_id) {
    if (!valid_key_id(key_id)) return Status::kInvalidArgument;
    const esp_efuse_block_t block = efuse_block_for(key_id);
    if (!esp_efuse_key_block_unused(block)) return Status::kEfuseStateInvalid;

    std::array<std::uint8_t, 32> key{};

    // This function is reached only in the dedicated pre-Wi-Fi production setup
    // mode. ESP-IDF documents that application-time esp_fill_random() is only
    // guaranteed true-random when RF or the internal SAR ADC entropy source is
    // active. Enable the latter for the shortest possible interval and disable
    // it before any normal Wi-Fi/ADC use can begin.
    bootloader_random_enable();
    esp_fill_random(key.data(), key.size());
    bootloader_random_disable();

    esp_err_t result = esp_efuse_batch_write_begin();
    if (result == ESP_OK) {
        // esp_efuse_write_key uses nested batch mode. The outer batch keeps the
        // key, HMAC_UP purpose, automatic read protection, and the two explicit
        // write-protection bits pending until the single final commit below.
        result = esp_efuse_write_key(
            block,
            ESP_EFUSE_KEY_PURPOSE_HMAC_UP,
            key.data(),
            key.size()
        );
    }
    if (result == ESP_OK) result = esp_efuse_set_key_dis_write(block);
    if (result == ESP_OK) result = esp_efuse_set_keypurpose_dis_write(block);

    if (result != ESP_OK) {
        (void)esp_efuse_batch_write_cancel();
        secure_zero(key.data(), key.size());
        return Status::kIrreversibleOperationFailed;
    }

    result = esp_efuse_batch_write_commit();
    secure_zero(key.data(), key.size());
    return result == ESP_OK ? Status::kOk : Status::kIrreversibleOperationFailed;
}

}  // namespace

const char* efuse_key_state_name(EfuseKeyState state) {
    switch (state) {
        case EfuseKeyState::kFree: return "free";
        case EfuseKeyState::kReusable: return "reusable";
        case EfuseKeyState::kIncompatible: return "incompatible";
    }
    return "incompatible";
}

HmacEfuseSecurityBackend::HmacEfuseSecurityBackend(std::uint8_t hmac_key_id)
    : hmac_key_id_(hmac_key_id) {}

Status HmacEfuseSecurityBackend::initialize_partition() {
    const ProductionSecurityStatus state = inspect(hmac_key_id_, burn_attempted_);
    if (!state.supported) return Status::kInvalidArgument;
    if (state.key_state == EfuseKeyState::kFree) return Status::kProductionInitRequired;
    if (state.key_state != EfuseKeyState::kReusable) return Status::kEfuseStateInvalid;
    return derive_and_initialize(hmac_key_id_);
}

Status HmacEfuseSecurityBackend::verify_encryption_active() {
    return verify_probe_not_plaintext();
}

Status HmacEfuseSecurityBackend::erase_user_partition() {
    return map_error(nvs_flash_erase_partition(kPartitionLabel));
}

std::string_view HmacEfuseSecurityBackend::profile() const {
    return "production-hmac-efuse";
}

bool HmacEfuseSecurityBackend::production_release_allowed() const {
    return true;
}

Status HmacEfuseSecurityBackend::production_security_status(
    ProductionSecurityStatus* status
) const {
    if (status == nullptr) return Status::kInvalidArgument;
    *status = inspect(hmac_key_id_, burn_attempted_);
    if (!status->supported) return Status::kInvalidArgument;
    return status->key_state == EfuseKeyState::kIncompatible
        ? Status::kEfuseStateInvalid
        : Status::kOk;
}

Status HmacEfuseSecurityBackend::initialize_production_security() {
    if (burn_attempted_) return Status::kIrreversibleOperationFailed;

    ProductionSecurityStatus state = inspect(hmac_key_id_, burn_attempted_);
    if (!state.supported) return Status::kInvalidArgument;
    if (state.key_state != EfuseKeyState::kFree) {
        // A reusable key is consumed by the normal read-only boot path. Reaching
        // this method with anything other than a free slot means the caller is
        // not in the first-time production initialization state; never erase
        // auth_nvs to "repair" another storage failure.
        return state.key_state == EfuseKeyState::kIncompatible
            ? Status::kEfuseStateInvalid
            : Status::kInvalidArgument;
    }

    // Latch before the first call that could physically program eFuse. Any
    // error after this point must be inspected manually; this boot will not make
    // another attempt.
    burn_attempted_ = true;
    const Status burn_status = burn_hmac_key_atomically(hmac_key_id_);
    if (burn_status != Status::kOk) return burn_status;

    state = inspect(hmac_key_id_, burn_attempted_);
    if (state.key_state != EfuseKeyState::kReusable) {
        return Status::kIrreversibleOperationFailed;
    }

    // First-time promotion is destructive only for the old development
    // auth_nvs contents. Existing reusable-key boots never take this path, so
    // unsupported schema/corruption cannot be converted into an implicit reset.
    return erase_user_partition();
}

}  // namespace m5auth::storage
