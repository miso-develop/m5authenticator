#include "m5auth/registration/registration.hpp"

#include <algorithm>
#include <array>
#include <cstdio>
#include <cstring>
#include <limits>

#include "esp_random.h"
#include "nvs.h"
#include "nvs_flash.h"

namespace m5auth::registration {
namespace {

// Registration/public Device identity is deliberately kept in the ordinary NVS
// partition, separate from the dedicated auth_nvs encrypted-Vault replica. A
// Vault format/reprovision erase can therefore never rotate the Device ID or
// silently discard the active BRK registration as a side effect.
constexpr char kNamespace[] = "m5auth_reg2";
constexpr char kDeviceIdKey[] = "device_id";
constexpr char kRegistrationKey[] = "active";
constexpr std::array<std::uint8_t, 8> kRegistrationMagic{
    'M', '5', 'A', 'R', 'E', 'G', '1', 0};
constexpr std::size_t kEncodedRegistrationBytes =
    kRegistrationMagic.size() + vault::kVaultIdBytes + kRegistrationIdBytes + 4 +
    session::kP256PublicKeyBytes;

bool all_zero(const auto& value) {
    return std::all_of(value.begin(), value.end(), [](std::uint8_t byte) { return byte == 0; });
}

Status map_error(esp_err_t error) {
    switch (error) {
        case ESP_OK: return Status::kOk;
        case ESP_ERR_NVS_NOT_FOUND:
        case ESP_ERR_NOT_FOUND: return Status::kNotFound;
        case ESP_ERR_INVALID_ARG: return Status::kInvalidArgument;
        default: return Status::kIo;
    }
}

bool valid_public_key(const BrkPublicKey& key) {
    return !all_zero(key) && key[0] == 0x04;
}

void write_u32(std::uint8_t* output, std::uint32_t value) {
    output[0] = static_cast<std::uint8_t>(value >> 24U);
    output[1] = static_cast<std::uint8_t>(value >> 16U);
    output[2] = static_cast<std::uint8_t>(value >> 8U);
    output[3] = static_cast<std::uint8_t>(value);
}

std::uint32_t read_u32(const std::uint8_t* input) {
    return (static_cast<std::uint32_t>(input[0]) << 24U) |
           (static_cast<std::uint32_t>(input[1]) << 16U) |
           (static_cast<std::uint32_t>(input[2]) << 8U) |
           static_cast<std::uint32_t>(input[3]);
}

Status open_namespace(nvs_open_mode_t mode, nvs_handle_t* handle) {
    if (handle == nullptr) return Status::kInvalidArgument;
    return map_error(nvs_open(kNamespace, mode, handle));
}

}  // namespace

const char* status_code(Status status) {
    switch (status) {
        case Status::kOk: return "ok";
        case Status::kNotFound: return "not_found";
        case Status::kInvalidArgument: return "invalid_argument";
        case Status::kConflict: return "registration_conflict";
        case Status::kCorrupt: return "registration_corrupt";
        case Status::kIo: return "registration_io_error";
    }
    return "registration_error";
}

void secure_zero(void* data, std::size_t size) {
    volatile auto* cursor = static_cast<volatile std::uint8_t*>(data);
    while (size-- > 0) *cursor++ = 0;
}

std::string device_id_text(const DeviceId& device_id) {
    char encoded[kDeviceIdBytes * 2 + 1]{};
    for (std::size_t index = 0; index < device_id.size(); ++index) {
        std::snprintf(
            encoded + index * 2,
            sizeof(encoded) - index * 2,
            "%02x",
            static_cast<unsigned>(device_id[index])
        );
    }
    return std::string(encoded);
}

void Store::generate_device_id_candidate() {
    do {
        esp_fill_random(snapshot_.device_id.data(), snapshot_.device_id.size());
    } while (all_zero(snapshot_.device_id));
}

Status Store::initialize() {
    ready_ = false;
    recovery_reset_available_ = false;
    device_id_recovery_required_ = false;
    snapshot_ = Snapshot{};

    // Never erase NVS implicitly here. Corrupt/newer NVS is a fail-closed state;
    // destructive recovery belongs to an explicit confirmed reset path.
    const esp_err_t nvs_status = nvs_flash_init();
    if (nvs_status != ESP_OK) return map_error(nvs_status);

    Status status = load_or_create_device_id();
    if (status == Status::kCorrupt) {
        // The persisted M5Authenticator-owned Device ID is structurally invalid.
        // Do not mutate NVS yet. Generate a fresh nonzero RAM candidate so the
        // explicit recovery-reset protocol has a stable identity before/after
        // confirmation; only clear_corrupt_registration_for_recovery() persists it.
        snapshot_ = Snapshot{};
        generate_device_id_candidate();
        recovery_reset_available_ = true;
        device_id_recovery_required_ = true;
        return status;
    }
    if (status != Status::kOk) return status;

    // Preserve the valid stable Device ID even when the active registration is
    // structurally corrupt. This is the only registration initialization failure
    // that can later enable the explicit destructive recovery path.
    const DeviceId stable_device_id = snapshot_.device_id;
    status = load_registration();
    if (status == Status::kCorrupt) {
        snapshot_ = Snapshot{};
        snapshot_.device_id = stable_device_id;
        recovery_reset_available_ = true;
        return status;
    }
    if (status != Status::kOk && status != Status::kNotFound) {
        snapshot_ = Snapshot{};
        return status;
    }
    ready_ = true;
    return Status::kOk;
}

Status Store::load_or_create_device_id() {
    nvs_handle_t handle = 0;
    Status status = open_namespace(NVS_READWRITE, &handle);
    if (status != Status::kOk) return status;

    std::size_t size = snapshot_.device_id.size();
    esp_err_t result = nvs_get_blob(handle, kDeviceIdKey, snapshot_.device_id.data(), &size);
    if (result == ESP_OK) {
        nvs_close(handle);
        if (size != snapshot_.device_id.size() || all_zero(snapshot_.device_id)) {
            snapshot_.device_id.fill(0);
            return Status::kCorrupt;
        }
        return Status::kOk;
    }
    if (result != ESP_ERR_NVS_NOT_FOUND) {
        nvs_close(handle);
        return map_error(result);
    }

    generate_device_id_candidate();

    result = nvs_set_blob(
        handle,
        kDeviceIdKey,
        snapshot_.device_id.data(),
        snapshot_.device_id.size()
    );
    if (result == ESP_OK) result = nvs_commit(handle);
    nvs_close(handle);
    if (result != ESP_OK) snapshot_.device_id.fill(0);
    return map_error(result);
}

Status Store::load_registration() {
    const DeviceId device_id = snapshot_.device_id;
    snapshot_ = Snapshot{};
    snapshot_.device_id = device_id;

    nvs_handle_t handle = 0;
    Status status = open_namespace(NVS_READONLY, &handle);
    if (status != Status::kOk) return status;

    std::array<std::uint8_t, kEncodedRegistrationBytes> encoded{};
    std::size_t size = encoded.size();
    const esp_err_t result = nvs_get_blob(handle, kRegistrationKey, encoded.data(), &size);
    nvs_close(handle);
    if (result == ESP_ERR_NVS_NOT_FOUND) return Status::kNotFound;
    if (result != ESP_OK) return map_error(result);
    if (size != encoded.size()) return Status::kCorrupt;

    std::size_t offset = 0;
    if (!std::equal(kRegistrationMagic.begin(), kRegistrationMagic.end(), encoded.begin())) {
        secure_zero(encoded.data(), encoded.size());
        return Status::kCorrupt;
    }
    offset += kRegistrationMagic.size();
    std::copy_n(encoded.data() + offset, snapshot_.vault_id.size(), snapshot_.vault_id.begin());
    offset += snapshot_.vault_id.size();
    std::copy_n(encoded.data() + offset, snapshot_.registration_id.size(), snapshot_.registration_id.begin());
    offset += snapshot_.registration_id.size();
    snapshot_.epoch = read_u32(encoded.data() + offset);
    offset += 4;
    std::copy_n(encoded.data() + offset, snapshot_.brk_public_key.size(), snapshot_.brk_public_key.begin());
    secure_zero(encoded.data(), encoded.size());

    if (all_zero(snapshot_.vault_id) || all_zero(snapshot_.registration_id) ||
        snapshot_.epoch == 0 || !valid_public_key(snapshot_.brk_public_key)) {
        snapshot_.registration_present = false;
        snapshot_.vault_id.fill(0);
        snapshot_.registration_id.fill(0);
        snapshot_.epoch = 0;
        snapshot_.brk_public_key.fill(0);
        return Status::kCorrupt;
    }
    snapshot_.registration_present = true;
    return Status::kOk;
}

Status Store::persist_registration(
    const VaultId& vault_id,
    const RegistrationId& registration_id,
    std::uint32_t epoch,
    const BrkPublicKey& brk_public_key
) {
    if (all_zero(vault_id) || all_zero(registration_id) || epoch == 0 || !valid_public_key(brk_public_key)) {
        return Status::kInvalidArgument;
    }

    std::array<std::uint8_t, kEncodedRegistrationBytes> encoded{};
    std::size_t offset = 0;
    std::copy(kRegistrationMagic.begin(), kRegistrationMagic.end(), encoded.begin());
    offset += kRegistrationMagic.size();
    std::copy(vault_id.begin(), vault_id.end(), encoded.begin() + static_cast<std::ptrdiff_t>(offset));
    offset += vault_id.size();
    std::copy(registration_id.begin(), registration_id.end(), encoded.begin() + static_cast<std::ptrdiff_t>(offset));
    offset += registration_id.size();
    write_u32(encoded.data() + offset, epoch);
    offset += 4;
    std::copy(brk_public_key.begin(), brk_public_key.end(), encoded.begin() + static_cast<std::ptrdiff_t>(offset));

    nvs_handle_t handle = 0;
    Status status = open_namespace(NVS_READWRITE, &handle);
    if (status != Status::kOk) {
        secure_zero(encoded.data(), encoded.size());
        return status;
    }
    esp_err_t result = nvs_set_blob(handle, kRegistrationKey, encoded.data(), encoded.size());
    if (result == ESP_OK) result = nvs_commit(handle);
    nvs_close(handle);
    secure_zero(encoded.data(), encoded.size());
    if (result != ESP_OK) return map_error(result);

    snapshot_.registration_present = true;
    snapshot_.vault_id = vault_id;
    snapshot_.registration_id = registration_id;
    snapshot_.epoch = epoch;
    snapshot_.brk_public_key = brk_public_key;
    return Status::kOk;
}

Status Store::snapshot(Snapshot* output) const {
    if (output == nullptr) return Status::kInvalidArgument;
    if (!ready_) {
        if (recovery_reset_available_) {
            *output = snapshot_;
            return Status::kCorrupt;
        }
        return Status::kIo;
    }
    *output = snapshot_;
    return Status::kOk;
}

Status Store::install_initial(
    const VaultId& vault_id,
    const RegistrationId& registration_id,
    std::uint32_t epoch,
    const BrkPublicKey& brk_public_key
) {
    if (!ready_) return Status::kIo;
    const Status refresh = load_registration();
    if (refresh != Status::kNotFound) {
        return refresh == Status::kOk ? Status::kConflict : refresh;
    }
    if (epoch != 1) return Status::kInvalidArgument;
    return persist_registration(vault_id, registration_id, epoch, brk_public_key);
}

Status Store::replace(
    const VaultId& vault_id,
    std::uint32_t expected_epoch,
    const RegistrationId& registration_id,
    std::uint32_t new_epoch,
    const BrkPublicKey& brk_public_key
) {
    if (!ready_ || expected_epoch == 0 || expected_epoch == std::numeric_limits<std::uint32_t>::max() ||
        new_epoch != expected_epoch + 1) {
        return Status::kInvalidArgument;
    }
    const Status refresh = load_registration();
    if (refresh != Status::kOk) return refresh;
    if (!snapshot_.registration_present || snapshot_.vault_id != vault_id || snapshot_.epoch != expected_epoch) {
        return Status::kConflict;
    }
    return persist_registration(vault_id, registration_id, new_epoch, brk_public_key);
}

Status Store::clear_registration() {
    if (!ready_) return Status::kIo;

    nvs_handle_t handle = 0;
    Status status = open_namespace(NVS_READWRITE, &handle);
    if (status != Status::kOk) return status;

    esp_err_t result = nvs_erase_key(handle, kRegistrationKey);
    if (result == ESP_ERR_NVS_NOT_FOUND) result = ESP_OK;
    if (result == ESP_OK) result = nvs_commit(handle);
    nvs_close(handle);
    if (result != ESP_OK) return map_error(result);

    const DeviceId device_id = snapshot_.device_id;
    snapshot_ = Snapshot{};
    snapshot_.device_id = device_id;
    recovery_reset_available_ = false;
    device_id_recovery_required_ = false;
    return Status::kOk;
}

Status Store::clear_corrupt_registration_for_recovery() {
    if (ready_) return clear_registration();
    if (!recovery_reset_available_ || all_zero(snapshot_.device_id)) return Status::kIo;

    const DeviceId recovery_device_id = snapshot_.device_id;
    nvs_handle_t handle = 0;
    Status status = open_namespace(NVS_READWRITE, &handle);
    if (status != Status::kOk) return status;

    esp_err_t result = ESP_OK;
    if (device_id_recovery_required_) {
        // Explicitly confirmed recovery of a structurally corrupt Device-ID
        // record clears only this application's registration namespace, then
        // persists the already-displayed RAM candidate as the new stable ID.
        result = nvs_erase_all(handle);
        if (result == ESP_OK) {
            result = nvs_set_blob(
                handle,
                kDeviceIdKey,
                recovery_device_id.data(),
                recovery_device_id.size()
            );
        }
    } else {
        result = nvs_erase_key(handle, kRegistrationKey);
        if (result == ESP_ERR_NVS_NOT_FOUND) result = ESP_OK;
    }
    if (result == ESP_OK) result = nvs_commit(handle);
    nvs_close(handle);
    if (result != ESP_OK) return map_error(result);

    snapshot_ = Snapshot{};
    snapshot_.device_id = recovery_device_id;
    recovery_reset_available_ = false;
    device_id_recovery_required_ = false;
    ready_ = true;
    return Status::kOk;
}

Status Store::reinitialize_after_partition_reset() {
    ready_ = false;
    recovery_reset_available_ = false;
    device_id_recovery_required_ = false;
    snapshot_ = Snapshot{};
    return initialize();
}

}  // namespace m5auth::registration
