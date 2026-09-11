#include "m5auth/vault_runtime/runtime.hpp"

#include <algorithm>
#include <array>
#include <cstdint>

#include "nvs.h"
#include "nvs_flash.h"

namespace m5auth::vault_runtime {
namespace {

constexpr char kPartitionLabel[] = "auth_nvs";
constexpr char kLegacyNamespace[] = "state";
constexpr char kLegacySchemaKey[] = "schema";

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
    const esp_err_t schema_result = nvs_get_u32(handle, kLegacySchemaKey, &schema);
    nvs_close(handle);
    (void)nvs_flash_deinit_partition(kPartitionLabel);
    return schema_result == ESP_OK && schema == 1;
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
    return schema2_.format_schema2();
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
    return schema2_.erase_all();
}

}  // namespace m5auth::vault_runtime
