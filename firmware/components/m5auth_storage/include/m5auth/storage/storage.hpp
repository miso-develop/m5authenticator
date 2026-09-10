#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>
#include <string_view>
#include <vector>

namespace m5auth::storage {

inline constexpr char kPartitionLabel[] = "auth_nvs";
inline constexpr std::size_t kMaxAccounts = 32;
inline constexpr std::size_t kMaxIssuerBytes = 96;
inline constexpr std::size_t kMaxAccountBytes = 128;
inline constexpr std::size_t kMaxDisplayNameBytes = 96;
inline constexpr std::size_t kMaxSecretBytes = 256;
inline constexpr std::size_t kMaxSsidBytes = 32;
inline constexpr std::size_t kMaxWifiPasswordBytes = 64;

// Storage errors intentionally carry only a failure class. Secret-bearing input is
// never embedded in error text or serialized responses.
enum class Status {
    kOk,
    kNotReady,
    kNotFound,
    kInvalidArgument,
    kFull,
    kUnsupportedSchema,
    kCorrupt,
    kIo,
    kSecurityInvariant,
};

const char* status_code(Status status);

struct AccountDraft {
    std::string issuer;
    std::string account;
    std::string display_name;
    std::string secret;
};

Status validate_account_draft(const AccountDraft& draft);

struct AccountMetadata {
    std::uint32_t id;
    std::uint16_t order;
    std::string issuer;
    std::string account;
    std::string display_name;
};

struct WifiStatus {
    bool configured;
    std::string ssid;
};

class SecurityBackend {
public:
    virtual ~SecurityBackend() = default;

    virtual Status initialize_partition() = 0;
    virtual Status verify_encryption_active() = 0;
    virtual Status erase_user_partition() = 0;
    virtual std::string_view profile() const = 0;
    virtual bool production_release_allowed() const = 0;
};

// Development-only backend. Its keys are deliberately public and synthetic.
// It exists only to exercise the encrypted NVS path without touching eFuse.
class DevSecurityBackend final : public SecurityBackend {
public:
    Status initialize_partition() override;
    Status verify_encryption_active() override;
    Status erase_user_partition() override;
    std::string_view profile() const override;
    bool production_release_allowed() const override;
};

class Store {
public:
    explicit Store(SecurityBackend& security_backend);

    Status initialize();
    bool ready() const;
    Status initialization_status() const;
    std::string_view security_profile() const;
    bool production_release_allowed() const;

    Status list_accounts(std::vector<AccountMetadata>* accounts) const;
    Status replace_accounts(const std::vector<AccountDraft>& accounts);
    Status add_account(const AccountDraft& account, std::uint32_t* new_id = nullptr);
    Status update_account(std::uint32_t id, const AccountDraft& account);
    Status rename_account(std::uint32_t id, std::string_view display_name);
    Status delete_account(std::uint32_t id);
    Status reorder_accounts(const std::vector<std::uint32_t>& ids);

    Status get_last_used(std::uint32_t* id) const;
    Status set_last_used(std::uint32_t id);

    Status wifi_status(WifiStatus* status) const;
    Status set_wifi(std::string_view ssid, std::string_view password);
    Status clear_wifi();

    using SecretConsumer = std::function<Status(std::string_view)>;
    Status with_account_secret(std::uint32_t id, const SecretConsumer& consumer) const;

    using WifiConsumer =
        std::function<Status(std::string_view ssid, std::string_view password)>;
    Status with_wifi_credentials(const WifiConsumer& consumer) const;

    Status factory_reset();

private:
    SecurityBackend& security_backend_;
    Status initialization_status_{Status::kNotReady};
};

void secure_zero(void* data, std::size_t size);
void secure_clear(std::string* value);

}  // namespace m5auth::storage
