#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>

#include "m5auth/session/session.hpp"
#include "m5auth/vault.hpp"

namespace m5auth::registration {

inline constexpr std::size_t kDeviceIdBytes = 16;
inline constexpr std::size_t kRegistrationIdBytes = 16;

using DeviceId = std::array<std::uint8_t, kDeviceIdBytes>;
using RegistrationId = std::array<std::uint8_t, kRegistrationIdBytes>;
using BrkPublicKey = session::P256PublicKey;
using VaultId = std::array<std::uint8_t, vault::kVaultIdBytes>;

enum class Status : std::uint8_t {
    kOk,
    kNotFound,
    kInvalidArgument,
    kConflict,
    kCorrupt,
    kIo,
};

const char* status_code(Status status);

struct Snapshot {
    DeviceId device_id{};
    bool registration_present{false};
    VaultId vault_id{};
    RegistrationId registration_id{};
    std::uint32_t epoch{0};
    BrkPublicKey brk_public_key{};
};

class Store final {
public:
    Status initialize();
    Status snapshot(Snapshot* output) const;

    Status install_initial(
        const VaultId& vault_id,
        const RegistrationId& registration_id,
        std::uint32_t epoch,
        const BrkPublicKey& brk_public_key
    );

    Status replace(
        const VaultId& vault_id,
        std::uint32_t expected_epoch,
        const RegistrationId& registration_id,
        std::uint32_t new_epoch,
        const BrkPublicKey& brk_public_key
    );

    // Factory Reset removes the active Trusted Browser registration but keeps
    // the stable, non-secret Device ID in the registration namespace.
    Status clear_registration();

    // Explicit recovery only: when initialize() proved that the stable Device
    // ID is valid but the registration blob is structurally corrupt, erase only
    // the M5Authenticator-owned active registration and restore a ready,
    // unregistered state. Generic NVS I/O failures never enable this path.
    bool recovery_reset_available() const { return recovery_reset_available_; }
    Status clear_corrupt_registration_for_recovery();

    // Used only after the auth_nvs partition has been explicitly erased/formatted.
    Status reinitialize_after_partition_reset();

    bool ready() const { return ready_; }

private:
    Status load_or_create_device_id();
    Status load_registration();
    Status persist_registration(
        const VaultId& vault_id,
        const RegistrationId& registration_id,
        std::uint32_t epoch,
        const BrkPublicKey& brk_public_key
    );

    bool ready_{false};
    bool recovery_reset_available_{false};
    Snapshot snapshot_{};
};

std::string device_id_text(const DeviceId& device_id);
void secure_zero(void* data, std::size_t size);

}  // namespace m5auth::registration
