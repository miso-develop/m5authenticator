#include "m5auth/vault_runtime/runtime.hpp"

#include <algorithm>
#include <array>
#include <cstdint>

#include "nvs.h"
#include "nvs_flash.h"

namespace m5auth::vault_runtime {
namespace {

constexpr char kPartitionLabel[] = "auth_nvs";
constexpr char kVaultNamespace[] = "vault2";
constexpr char kLegacyNamespace[] = "state";
constexpr char kSchemaKey[] = "schema";

// PUBLIC SYNTHETIC DEVELOPMENT-ONLY keys copied from the superseded Schema 1
// backend. They are not a V1 protection boundary. They are retained here only
// so an existing development partition can be positively identified and
// rejected with kReprovisionRequired instead of being misclassified as corrupt.
constexpr std::array<std::uint8_t, NVS_KEY_SIZE> kLegacyDevEncryptionKey{
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
};
constexpr std::array<std::uint8_t, NVS_KEY_SIZE> kLegacyDevTweakKey{
    0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
    0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
    0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7,
    0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf,
};

Status map_error(esp_err_t error) {
    switch (error) {
        case ESP_OK: return Status::kOk;
        case ESP_ERR_NVS_NOT_FOUND:
        case ESP_ERR_NOT_FOUND: return Status::kNotFound;
        case ESP_ERR_INVALID_ARG: return Status::kInvalidArgument;
        case ESP_ERR_NVS_NO_FREE_PAGES: return Status::kCorrupt;
        case ESP_ERR_NVS_NEW_VERSION_FOUND: return Status::kUnsupportedSchema;
        default: return Status::kIo;
    }
}

void wipe_config(nvs_sec_cfg_t* config) {
    if (config == nullptr) return;
    volatile auto* cursor = reinterpret_cast<volatile std::uint8_t*>(config);
    std::size_t remaining = sizeof(*config);
    while (remaining-- > 0) {
        *cursor++ = 0;
    }
}

bool legacy_schema1_present() {
    // The Schema 2 path may already have initialized this partition without a
    // security config. Tear that view down before the legacy read-only probe.
    (void)nvs_flash_deinit_partition(kPartitionLabel);

    nvs_sec_cfg_t config{};
    std::copy(
        kLegacyDevEncryptionKey.begin(),
        kLegacyDevEncryptionKey.end(),
        config.eky
    );
    std::copy(
        kLegacyDevTweakKey.begin(),
        kLegacyDevTweakKey.end(),
        config.tky
    );

    const esp_err_t init_result =
        nvs_flash_secure_init_partition(kPartitionLabel, &config);
    wipe_config(&config);
    if (init_result != ESP_OK) {
        (void)nvs_flash_deinit_partition(kPartitionLabel);
        return false;
    }

    nvs_handle_t handle = 0;
    const esp_err_t open_result = nvs_open_from_partition(
        kPartitionLabel,
        kLegacyNamespace,
        NVS_READONLY,
        &handle
    );
    if (open_result != ESP_OK) {
        (void)nvs_flash_deinit_partition(kPartitionLabel);
        return false;
    }

    std::uint32_t schema = 0;
    const esp_err_t schema_result = nvs_get_u32(handle, kSchemaKey, &schema);
    nvs_close(handle);
    (void)nvs_flash_deinit_partition(kPartitionLabel);
    return schema_result == ESP_OK && schema == 1;
}

Status initialize_plain_partition() {
    (void)nvs_flash_deinit_partition(kPartitionLabel);
    return map_error(nvs_flash_init_partition(kPartitionLabel));
}

Status erase_namespace(const char* name) {
    nvs_handle_t handle = 0;
    const esp_err_t open_result = nvs_open_from_partition(
        kPartitionLabel,
        name,
        NVS_READWRITE,
        &handle
    );
    if (open_result != ESP_OK) return map_error(open_result);
    esp_err_t result = nvs_erase_all(handle);
    if (result == ESP_OK) result = nvs_commit(handle);
    nvs_close(handle);
    return map_error(result);
}

Status write_empty_schema2_namespace() {
    nvs_handle_t handle = 0;
    const esp_err_t open_result = nvs_open_from_partition(
        kPartitionLabel,
        kVaultNamespace,
        NVS_READWRITE,
        &handle
    );
    if (open_result != ESP_OK) return map_error(open_result);

    esp_err_t result = nvs_erase_all(handle);
    if (result == ESP_OK) {
        result = nvs_set_u32(handle, kSchemaKey, kStorageSchemaVersion);
    }
    if (result == ESP_OK) result = nvs_commit(handle);
    nvs_close(handle);
    return map_error(result);
}

Status full_erase_and_initialize_schema2() {
    (void)nvs_flash_deinit_partition(kPartitionLabel);
    esp_err_t result = nvs_flash_erase_partition(kPartitionLabel);
    if (result != ESP_OK) return map_error(result);
    result = nvs_flash_init_partition(kPartitionLabel);
    if (result != ESP_OK) return map_error(result);
    return write_empty_schema2_namespace();
}

Status clear_vault_namespaces_preserving_registration(bool create_schema) {
    // A legacy Schema 1 partition used NVS encryption with public development
    // keys. It cannot safely coexist with the canonical plaintext-NVS framing;
    // explicit reprovision therefore performs the historical full partition
    // erase. No canonical reg2 identity can predate that migration boundary.
    if (legacy_schema1_present()) {
        return create_schema
            ? full_erase_and_initialize_schema2()
            : full_erase_and_initialize_schema2();
    }

    Status status = initialize_plain_partition();
    if (status != Status::kOk) return status;

    status = erase_namespace(kLegacyNamespace);
    if (status != Status::kOk) return status;

    if (create_schema) return write_empty_schema2_namespace();
    return erase_namespace(kVaultNamespace);
}

}  // namespace

Status CompatibleNvsPersistence::load(PersistedSnapshot* snapshot) {
    if (snapshot == nullptr) return Status::kInvalidArgument;

    const Status primary = schema2_.load(snapshot);
    if (primary == Status::kOk || primary == Status::kReprovisionRequired) {
        return primary;
    }

    if (legacy_schema1_present()) {
        *snapshot = PersistedSnapshot{};
        return Status::kReprovisionRequired;
    }

    // Never convert an unknown/corrupt/newer state into an automatic reset or
    // migration. Preserve the Schema 2 adapter's original fail-closed result.
    return primary;
}

Status CompatibleNvsPersistence::format_schema2() {
    // Canonical registration/device identity now lives in a separate `reg2`
    // namespace on the same auth_nvs partition. Normal first provisioning and
    // reprovisioning of an already canonical Device must therefore clear only
    // Vault/legacy user-state namespaces, not the whole partition.
    return clear_vault_namespaces_preserving_registration(true);
}

Status CompatibleNvsPersistence::replace_envelope(
    std::uint64_t expected_generation,
    const vault::VaultEnvelope& envelope
) {
    return schema2_.replace_envelope(expected_generation, envelope);
}

Status CompatibleNvsPersistence::set_last_used(
    const std::optional<CredentialId>& credential_id
) {
    return schema2_.set_last_used(credential_id);
}

Status CompatibleNvsPersistence::erase_all() {
    // Factory Reset clears Vault/user data while the registration component
    // separately removes the active BRK registration. Device ID remains stable
    // across reset so a USB-visible identity cannot change as a side effect of
    // deleting user credentials.
    return clear_vault_namespaces_preserving_registration(false);
}

}  // namespace m5auth::vault_runtime
