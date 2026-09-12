#pragma once

namespace m5auth::core {

inline constexpr char kFirmwareVersion[] = "0.1.0";
inline constexpr int kProtocolVersion = 2;
inline constexpr int kStorageSchemaVersion = 2;
inline constexpr int kVaultFormatVersion = 1;

struct DeviceMetadata {
    const char* device;
    const char* firmware;
    int protocol;
    int storage_schema;
    int vault_format;
    const char* build_commit;
};

inline constexpr DeviceMetadata metadata_for(
    const char* device,
    const char* build_commit
) {
    return DeviceMetadata{
        .device = device,
        .firmware = kFirmwareVersion,
        .protocol = kProtocolVersion,
        .storage_schema = kStorageSchemaVersion,
        .vault_format = kVaultFormatVersion,
        .build_commit = build_commit,
    };
}

}  // namespace m5auth::core
