#include "m5auth/storage/storage.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <limits>
#include <utility>

#include "esp_partition.h"
#include "m5auth/core/metadata.hpp"
#include "nvs.h"
#include "nvs_flash.h"
#include "state.hpp"

namespace m5auth::storage {
namespace {

constexpr char kStateNamespace[] = "state";
constexpr char kSchemaKey[] = "schema";
constexpr char kSnapshotKey[] = "snapshot";
constexpr char kProbeNamespace[] = "dev_probe";
constexpr char kProbeKey[] = "probe";
constexpr std::array<std::uint8_t, 28> kProbeValue{
    'M', '5', 'A', 'U', 'T', 'H', '-', 'D', 'E', 'V', '-', 'E', 'N', 'C', '-',
    'P', 'R', 'O', 'B', 'E', '-', 'V', '1', '-', 'S', 'A', 'F', 'E'};

// PUBLIC SYNTHETIC DEVELOPMENT-ONLY keys. These are intentionally not secret
// and must never be used by a production build. Production HMAC/eFuse keying is
// owned exclusively by Task #26.
constexpr std::array<std::uint8_t, NVS_KEY_SIZE> kDevEncryptionKey{
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
};
constexpr std::array<std::uint8_t, NVS_KEY_SIZE> kDevTweakKey{
    0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
    0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
    0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7,
    0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf,
};

Status map_esp_error(esp_err_t error) {
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
        default:
            return Status::kIo;
    }
}

Status open_state(nvs_open_mode_t mode, nvs_handle_t* handle) {
    return map_esp_error(nvs_open_from_partition(
        kPartitionLabel,
        kStateNamespace,
        mode,
        handle
    ));
}

Status read_schema(std::uint32_t* schema) {
    if (schema == nullptr) {
        return Status::kInvalidArgument;
    }
    nvs_handle_t handle = 0;
    const Status open_status = open_state(NVS_READONLY, &handle);
    if (open_status != Status::kOk) {
        return open_status;
    }
    const esp_err_t result = nvs_get_u32(handle, kSchemaKey, schema);
    nvs_close(handle);
    return map_esp_error(result);
}

Status save_state_unchecked(const internal::State& state) {
    std::vector<std::uint8_t> encoded;
    Status status = internal::encode_state(state, &encoded);
    if (status != Status::kOk) {
        return status;
    }

    nvs_handle_t handle = 0;
    status = open_state(NVS_READWRITE, &handle);
    if (status != Status::kOk) {
        internal::secure_clear_bytes(&encoded);
        return status;
    }

    esp_err_t result = nvs_set_blob(
        handle,
        kSnapshotKey,
        encoded.data(),
        encoded.size()
    );
    if (result == ESP_OK) {
        result = nvs_commit(handle);
    }
    nvs_close(handle);
    internal::secure_clear_bytes(&encoded);
    return map_esp_error(result);
}

Status initialize_fresh_state() {
    internal::State empty;
    std::vector<std::uint8_t> encoded;
    Status status = internal::encode_state(empty, &encoded);
    if (status != Status::kOk) {
        return status;
    }

    nvs_handle_t handle = 0;
    status = open_state(NVS_READWRITE, &handle);
    if (status != Status::kOk) {
        internal::secure_clear_bytes(&encoded);
        return status;
    }

    esp_err_t result = nvs_set_blob(
        handle,
        kSnapshotKey,
        encoded.data(),
        encoded.size()
    );
    if (result == ESP_OK) {
        result = nvs_set_u32(handle, kSchemaKey, core::kStorageSchemaVersion);
    }
    if (result == ESP_OK) {
        result = nvs_commit(handle);
    }
    nvs_close(handle);
    internal::secure_clear_bytes(&encoded);
    return map_esp_error(result);
}

Status load_state_unchecked(internal::State* state) {
    if (state == nullptr) {
        return Status::kInvalidArgument;
    }

    nvs_handle_t handle = 0;
    Status status = open_state(NVS_READONLY, &handle);
    if (status != Status::kOk) {
        return status;
    }

    std::size_t size = 0;
    esp_err_t result = nvs_get_blob(handle, kSnapshotKey, nullptr, &size);
    if (result != ESP_OK || size == 0 || size > 64 * 1024) {
        nvs_close(handle);
        return result == ESP_OK ? Status::kCorrupt : map_esp_error(result);
    }

    std::vector<std::uint8_t> encoded(size);
    result = nvs_get_blob(handle, kSnapshotKey, encoded.data(), &size);
    nvs_close(handle);
    if (result != ESP_OK) {
        internal::secure_clear_bytes(&encoded);
        return map_esp_error(result);
    }

    status = internal::decode_state(encoded.data(), encoded.size(), state);
    internal::secure_clear_bytes(&encoded);
    return status;
}

bool contains_plain_probe(const esp_partition_t* partition, Status* status) {
    if (partition == nullptr || status == nullptr) {
        if (status != nullptr) {
            *status = Status::kInvalidArgument;
        }
        return false;
    }

    constexpr std::size_t kChunkSize = 256;
    std::array<std::uint8_t, kChunkSize + kProbeValue.size() - 1> buffer{};
    std::size_t carry = 0;
    std::size_t offset = 0;

    while (offset < partition->size) {
        const std::size_t chunk = std::min(
            kChunkSize,
            static_cast<std::size_t>(partition->size - offset)
        );
        const esp_err_t result = esp_partition_read(
            partition,
            offset,
            buffer.data() + carry,
            chunk
        );
        if (result != ESP_OK) {
            *status = map_esp_error(result);
            return false;
        }

        const std::size_t available = carry + chunk;
        const auto end = buffer.begin() + static_cast<std::ptrdiff_t>(available);
        const auto found = std::search(
            buffer.begin(),
            end,
            kProbeValue.begin(),
            kProbeValue.end()
        );
        if (found != end) {
            *status = Status::kSecurityInvariant;
            return true;
        }

        carry = std::min(kProbeValue.size() - 1, available);
        if (carry > 0) {
            std::memmove(
                buffer.data(),
                buffer.data() + available - carry,
                carry
            );
        }
        offset += chunk;
    }

    *status = Status::kOk;
    return false;
}

Status require_ready(Status initialization_status) {
    return initialization_status == Status::kOk
        ? Status::kOk
        : initialization_status;
}

Status validate_display_name(std::string_view display_name) {
    return display_name.size() <= kMaxDisplayNameBytes
        ? Status::kOk
        : Status::kInvalidArgument;
}

}  // namespace

const char* status_code(Status status) {
    switch (status) {
        case Status::kOk:
            return "ok";
        case Status::kNotReady:
            return "storage_not_ready";
        case Status::kNotFound:
            return "not_found";
        case Status::kInvalidArgument:
            return "invalid_argument";
        case Status::kFull:
            return "storage_full";
        case Status::kUnsupportedSchema:
            return "unsupported_schema";
        case Status::kCorrupt:
            return "storage_corrupt";
        case Status::kIo:
            return "storage_io";
        case Status::kSecurityInvariant:
            return "security_invariant";
        case Status::kProductionInitRequired:
            return "production_init_required";
        case Status::kEfuseStateInvalid:
            return "efuse_state_invalid";
        case Status::kIrreversibleOperationFailed:
            return "irreversible_operation_failed";
    }
    return "storage_error";
}

Status DevSecurityBackend::initialize_partition() {
    nvs_sec_cfg_t config{};
    std::copy(kDevEncryptionKey.begin(), kDevEncryptionKey.end(), config.eky);
    std::copy(kDevTweakKey.begin(), kDevTweakKey.end(), config.tky);

    const esp_err_t result = nvs_flash_secure_init_partition(kPartitionLabel, &config);
    internal::secure_zero(&config, sizeof(config));
    return map_esp_error(result);
}

Status DevSecurityBackend::verify_encryption_active() {
    nvs_handle_t handle = 0;
    esp_err_t result = nvs_open_from_partition(
        kPartitionLabel,
        kProbeNamespace,
        NVS_READWRITE,
        &handle
    );
    if (result != ESP_OK) {
        return map_esp_error(result);
    }

    result = nvs_set_blob(handle, kProbeKey, kProbeValue.data(), kProbeValue.size());
    if (result == ESP_OK) {
        result = nvs_commit(handle);
    }
    nvs_close(handle);
    if (result != ESP_OK) {
        return map_esp_error(result);
    }

    const esp_partition_t* partition = esp_partition_find_first(
        ESP_PARTITION_TYPE_DATA,
        ESP_PARTITION_SUBTYPE_DATA_NVS,
        kPartitionLabel
    );
    if (partition == nullptr) {
        return Status::kNotFound;
    }

    Status scan_status = Status::kOk;
    const bool plaintext_found = contains_plain_probe(partition, &scan_status);

    handle = 0;
    result = nvs_open_from_partition(
        kPartitionLabel,
        kProbeNamespace,
        NVS_READWRITE,
        &handle
    );
    if (result == ESP_OK) {
        result = nvs_erase_key(handle, kProbeKey);
        if (result == ESP_ERR_NVS_NOT_FOUND) {
            result = ESP_OK;
        }
        if (result == ESP_OK) {
            result = nvs_commit(handle);
        }
        nvs_close(handle);
    }

    if (plaintext_found || scan_status != Status::kOk) {
        return scan_status;
    }
    return map_esp_error(result);
}

Status DevSecurityBackend::erase_user_partition() {
    return map_esp_error(nvs_flash_erase_partition(kPartitionLabel));
}

std::string_view DevSecurityBackend::profile() const {
    return "development";
}

bool DevSecurityBackend::production_release_allowed() const {
    return false;
}

Store::Store(SecurityBackend& security_backend)
    : security_backend_(security_backend) {}

Status Store::initialize() {
    initialization_status_ = security_backend_.initialize_partition();
    if (initialization_status_ != Status::kOk) {
        return initialization_status_;
    }

    std::uint32_t schema = 0;
    Status schema_status = read_schema(&schema);
    if (schema_status == Status::kNotFound) {
        initialization_status_ = initialize_fresh_state();
        if (initialization_status_ != Status::kOk) {
            return initialization_status_;
        }
        schema = core::kStorageSchemaVersion;
    } else if (schema_status != Status::kOk) {
        initialization_status_ = schema_status;
        return initialization_status_;
    }

    if (schema != static_cast<std::uint32_t>(core::kStorageSchemaVersion)) {
        initialization_status_ = Status::kUnsupportedSchema;
        return initialization_status_;
    }

    initialization_status_ = security_backend_.verify_encryption_active();
    if (initialization_status_ != Status::kOk) {
        return initialization_status_;
    }

    internal::State state;
    initialization_status_ = load_state_unchecked(&state);
    internal::wipe_state(&state);
    return initialization_status_;
}

bool Store::ready() const {
    return initialization_status_ == Status::kOk;
}

Status Store::initialization_status() const {
    return initialization_status_;
}

std::string_view Store::security_profile() const {
    return security_backend_.profile();
}

bool Store::production_release_allowed() const {
    return security_backend_.production_release_allowed();
}

Status Store::list_accounts(std::vector<AccountMetadata>* accounts) const {
    if (accounts == nullptr) {
        return Status::kInvalidArgument;
    }
    const Status ready_status = require_ready(initialization_status_);
    if (ready_status != Status::kOk) {
        return ready_status;
    }

    internal::State state;
    Status status = load_state_unchecked(&state);
    if (status != Status::kOk) {
        internal::wipe_state(&state);
        return status;
    }

    accounts->clear();
    accounts->reserve(state.accounts.size());
    for (const auto& account : state.accounts) {
        accounts->push_back(AccountMetadata{
            .id = account.id,
            .order = account.order,
            .issuer = account.issuer,
            .account = account.account,
            .display_name = account.display_name,
        });
    }
    std::sort(
        accounts->begin(),
        accounts->end(),
        [](const AccountMetadata& left, const AccountMetadata& right) {
            return left.order < right.order;
        }
    );
    internal::wipe_state(&state);
    return Status::kOk;
}

Status Store::replace_accounts(const std::vector<AccountDraft>& accounts) {
    const Status ready_status = require_ready(initialization_status_);
    if (ready_status != Status::kOk) {
        return ready_status;
    }
    if (accounts.size() > kMaxAccounts) {
        return Status::kFull;
    }
    for (const auto& account : accounts) {
        const Status status = internal::validate_account_draft(account);
        if (status != Status::kOk) {
            return status;
        }
    }

    internal::State state;
    Status status = load_state_unchecked(&state);
    if (status != Status::kOk) {
        internal::wipe_state(&state);
        return status;
    }

    for (auto& existing : state.accounts) {
        internal::secure_clear(&existing.secret);
    }
    state.accounts.clear();
    state.last_used_id = 0;

    for (std::size_t index = 0; index < accounts.size(); ++index) {
        if (state.next_id == 0 || state.next_id == std::numeric_limits<std::uint32_t>::max()) {
            internal::wipe_state(&state);
            return Status::kFull;
        }
        const auto& source = accounts[index];
        state.accounts.push_back(internal::AccountRecord{
            .id = state.next_id++,
            .order = static_cast<std::uint16_t>(index),
            .issuer = source.issuer,
            .account = source.account,
            .display_name = source.display_name,
            .secret = source.secret,
        });
    }

    status = save_state_unchecked(state);
    internal::wipe_state(&state);
    return status;
}

Status Store::add_account(const AccountDraft& account, std::uint32_t* new_id) {
    const Status ready_status = require_ready(initialization_status_);
    if (ready_status != Status::kOk) {
        return ready_status;
    }
    Status status = internal::validate_account_draft(account);
    if (status != Status::kOk) {
        return status;
    }

    internal::State state;
    status = load_state_unchecked(&state);
    if (status != Status::kOk) {
        internal::wipe_state(&state);
        return status;
    }
    if (state.accounts.size() >= kMaxAccounts || state.next_id == 0 ||
        state.next_id == std::numeric_limits<std::uint32_t>::max()) {
        internal::wipe_state(&state);
        return Status::kFull;
    }

    const std::uint32_t id = state.next_id++;
    state.accounts.push_back(internal::AccountRecord{
        .id = id,
        .order = static_cast<std::uint16_t>(state.accounts.size()),
        .issuer = account.issuer,
        .account = account.account,
        .display_name = account.display_name,
        .secret = account.secret,
    });
    status = save_state_unchecked(state);
    internal::wipe_state(&state);
    if (status == Status::kOk && new_id != nullptr) {
        *new_id = id;
    }
    return status;
}

Status Store::update_account(std::uint32_t id, const AccountDraft& account) {
    const Status ready_status = require_ready(initialization_status_);
    if (ready_status != Status::kOk) {
        return ready_status;
    }
    if (id == 0) {
        return Status::kInvalidArgument;
    }
    Status status = internal::validate_account_draft(account);
    if (status != Status::kOk) {
        return status;
    }

    internal::State state;
    status = load_state_unchecked(&state);
    if (status != Status::kOk) {
        internal::wipe_state(&state);
        return status;
    }

    auto found = std::find_if(
        state.accounts.begin(),
        state.accounts.end(),
        [id](const internal::AccountRecord& item) { return item.id == id; }
    );
    if (found == state.accounts.end()) {
        internal::wipe_state(&state);
        return Status::kNotFound;
    }

    found->issuer = account.issuer;
    found->account = account.account;
    found->display_name = account.display_name;
    internal::secure_clear(&found->secret);
    found->secret = account.secret;

    status = save_state_unchecked(state);
    internal::wipe_state(&state);
    return status;
}

Status Store::rename_account(std::uint32_t id, std::string_view display_name) {
    const Status ready_status = require_ready(initialization_status_);
    if (ready_status != Status::kOk) {
        return ready_status;
    }
    if (id == 0 || validate_display_name(display_name) != Status::kOk) {
        return Status::kInvalidArgument;
    }

    internal::State state;
    Status status = load_state_unchecked(&state);
    if (status != Status::kOk) {
        internal::wipe_state(&state);
        return status;
    }
    auto found = std::find_if(
        state.accounts.begin(),
        state.accounts.end(),
        [id](const internal::AccountRecord& item) { return item.id == id; }
    );
    if (found == state.accounts.end()) {
        internal::wipe_state(&state);
        return Status::kNotFound;
    }
    found->display_name.assign(display_name.data(), display_name.size());
    status = save_state_unchecked(state);
    internal::wipe_state(&state);
    return status;
}

Status Store::delete_account(std::uint32_t id) {
    const Status ready_status = require_ready(initialization_status_);
    if (ready_status != Status::kOk) {
        return ready_status;
    }
    if (id == 0) {
        return Status::kInvalidArgument;
    }

    internal::State state;
    Status status = load_state_unchecked(&state);
    if (status != Status::kOk) {
        internal::wipe_state(&state);
        return status;
    }
    auto found = std::find_if(
        state.accounts.begin(),
        state.accounts.end(),
        [id](const internal::AccountRecord& item) { return item.id == id; }
    );
    if (found == state.accounts.end()) {
        internal::wipe_state(&state);
        return Status::kNotFound;
    }

    internal::secure_clear(&found->secret);
    state.accounts.erase(found);
    std::sort(
        state.accounts.begin(),
        state.accounts.end(),
        [](const internal::AccountRecord& left, const internal::AccountRecord& right) {
            return left.order < right.order;
        }
    );
    for (std::size_t index = 0; index < state.accounts.size(); ++index) {
        state.accounts[index].order = static_cast<std::uint16_t>(index);
    }
    if (state.last_used_id == id) {
        state.last_used_id = 0;
    }

    status = save_state_unchecked(state);
    internal::wipe_state(&state);
    return status;
}

Status Store::reorder_accounts(const std::vector<std::uint32_t>& ids) {
    const Status ready_status = require_ready(initialization_status_);
    if (ready_status != Status::kOk) {
        return ready_status;
    }

    internal::State state;
    Status status = load_state_unchecked(&state);
    if (status != Status::kOk) {
        internal::wipe_state(&state);
        return status;
    }
    if (ids.size() != state.accounts.size()) {
        internal::wipe_state(&state);
        return Status::kInvalidArgument;
    }

    std::vector<bool> seen(state.accounts.size(), false);
    for (std::size_t order = 0; order < ids.size(); ++order) {
        auto found = std::find_if(
            state.accounts.begin(),
            state.accounts.end(),
            [id = ids[order]](const internal::AccountRecord& item) {
                return item.id == id;
            }
        );
        if (found == state.accounts.end()) {
            internal::wipe_state(&state);
            return Status::kInvalidArgument;
        }
        const std::size_t index = static_cast<std::size_t>(found - state.accounts.begin());
        if (seen[index]) {
            internal::wipe_state(&state);
            return Status::kInvalidArgument;
        }
        seen[index] = true;
        found->order = static_cast<std::uint16_t>(order);
    }

    status = save_state_unchecked(state);
    internal::wipe_state(&state);
    return status;
}

Status Store::get_last_used(std::uint32_t* id) const {
    if (id == nullptr) {
        return Status::kInvalidArgument;
    }
    const Status ready_status = require_ready(initialization_status_);
    if (ready_status != Status::kOk) {
        return ready_status;
    }
    internal::State state;
    const Status status = load_state_unchecked(&state);
    if (status == Status::kOk) {
        *id = state.last_used_id;
    }
    internal::wipe_state(&state);
    return status;
}

Status Store::set_last_used(std::uint32_t id) {
    const Status ready_status = require_ready(initialization_status_);
    if (ready_status != Status::kOk) {
        return ready_status;
    }
    if (id == 0) {
        return Status::kInvalidArgument;
    }
    internal::State state;
    Status status = load_state_unchecked(&state);
    if (status != Status::kOk) {
        internal::wipe_state(&state);
        return status;
    }
    const bool exists = std::any_of(
        state.accounts.begin(),
        state.accounts.end(),
        [id](const internal::AccountRecord& item) { return item.id == id; }
    );
    if (!exists) {
        internal::wipe_state(&state);
        return Status::kNotFound;
    }
    state.last_used_id = id;
    status = save_state_unchecked(state);
    internal::wipe_state(&state);
    return status;
}

Status Store::wifi_status(WifiStatus* status_output) const {
    if (status_output == nullptr) {
        return Status::kInvalidArgument;
    }
    const Status ready_status = require_ready(initialization_status_);
    if (ready_status != Status::kOk) {
        return ready_status;
    }
    internal::State state;
    const Status status = load_state_unchecked(&state);
    if (status == Status::kOk) {
        status_output->configured = !state.wifi_ssid.empty() && !state.wifi_password.empty();
        status_output->ssid = state.wifi_ssid;
    }
    internal::wipe_state(&state);
    return status;
}

Status Store::set_wifi(std::string_view ssid, std::string_view password) {
    const Status ready_status = require_ready(initialization_status_);
    if (ready_status != Status::kOk) {
        return ready_status;
    }
    if (ssid.empty() || ssid.size() > kMaxSsidBytes || password.empty() ||
        password.size() > kMaxWifiPasswordBytes) {
        return Status::kInvalidArgument;
    }

    internal::State state;
    Status status = load_state_unchecked(&state);
    if (status != Status::kOk) {
        internal::wipe_state(&state);
        return status;
    }
    state.wifi_ssid.assign(ssid.data(), ssid.size());
    internal::secure_clear(&state.wifi_password);
    state.wifi_password.assign(password.data(), password.size());
    status = save_state_unchecked(state);
    internal::wipe_state(&state);
    return status;
}

Status Store::clear_wifi() {
    const Status ready_status = require_ready(initialization_status_);
    if (ready_status != Status::kOk) {
        return ready_status;
    }
    internal::State state;
    Status status = load_state_unchecked(&state);
    if (status != Status::kOk) {
        internal::wipe_state(&state);
        return status;
    }
    state.wifi_ssid.clear();
    internal::secure_clear(&state.wifi_password);
    status = save_state_unchecked(state);
    internal::wipe_state(&state);
    return status;
}

Status Store::with_account_secret(
    std::uint32_t id,
    const SecretConsumer& consumer
) const {
    const Status ready_status = require_ready(initialization_status_);
    if (ready_status != Status::kOk) {
        return ready_status;
    }
    if (id == 0 || !consumer) {
        return Status::kInvalidArgument;
    }
    internal::State state;
    Status status = load_state_unchecked(&state);
    if (status != Status::kOk) {
        internal::wipe_state(&state);
        return status;
    }
    auto found = std::find_if(
        state.accounts.begin(),
        state.accounts.end(),
        [id](const internal::AccountRecord& item) { return item.id == id; }
    );
    if (found == state.accounts.end()) {
        internal::wipe_state(&state);
        return Status::kNotFound;
    }
    status = consumer(found->secret);
    internal::wipe_state(&state);
    return status;
}

Status Store::with_wifi_credentials(const WifiConsumer& consumer) const {
    const Status ready_status = require_ready(initialization_status_);
    if (ready_status != Status::kOk) {
        return ready_status;
    }
    if (!consumer) {
        return Status::kInvalidArgument;
    }
    internal::State state;
    Status status = load_state_unchecked(&state);
    if (status != Status::kOk) {
        internal::wipe_state(&state);
        return status;
    }
    if (state.wifi_ssid.empty() || state.wifi_password.empty()) {
        internal::wipe_state(&state);
        return Status::kNotFound;
    }
    status = consumer(state.wifi_ssid, state.wifi_password);
    internal::wipe_state(&state);
    return status;
}

Status Store::factory_reset() {
    const Status erase_status = security_backend_.erase_user_partition();
    if (erase_status != Status::kOk) {
        initialization_status_ = erase_status;
        return erase_status;
    }
    initialization_status_ = Status::kNotReady;
    return initialize();
}

}  // namespace m5auth::storage
