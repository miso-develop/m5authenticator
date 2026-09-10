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
    kProductionInitRequired,
    kEfuseStateInvalid,
    kIrreversibleOperationFailed,
};

const char* status_code(Status status);

struct AccountDraft {
    std::string issuer;
    std::string account;
    std::string display_name;
    std::string secret;

    AccountDraft() = default;
    AccountDraft(const AccountDraft&) = default;
    AccountDraft& operator=(const AccountDraft&) = default;
    AccountDraft(AccountDraft&& other) noexcept;
    AccountDraft& operator=(AccountDraft&& other) noexcept;
    ~AccountDraft();
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

enum class EfuseKeyState {
    kFree,
    kReusable,
    kIncompatible,
};

const char* efuse_key_state_name(EfuseKeyState state);

struct ProductionSecurityStatus {
    bool supported{false};
    std::uint8_t hmac_key_id{0};
    EfuseKeyState key_state{EfuseKeyState::kIncompatible};
    bool read_protected{false};
    bool write_protected{false};
    bool purpose_write_protected{false};
    unsigned unused_key_blocks{0};
    bool burn_attempted{false};
};

// Pure policy gate for the only state that may cross the irreversible
// production-initialization boundary. This intentionally excludes reusable keys
// and every non-first-time storage failure.
bool production_initialization_eligible(
    Status initialization_status,
    Status security_status,
    const ProductionSecurityStatus& security
);

class SecurityBackend {
public:
    virtual ~SecurityBackend() = default;

    virtual Status initialize_partition() = 0;
    virtual Status verify_encryption_active() = 0;
    virtual Status erase_user_partition() = 0;
    virtual std::string_view profile() const = 0;
    virtual bool production_release_allowed() const = 0;
    virtual Status production_security_status(ProductionSecurityStatus* status) const = 0;
    virtual Status initialize_production_security() = 0;
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
    Status production_security_status(ProductionSecurityStatus* status) const override;
    Status initialize_production_security() override;
};

// Production backend. Normal initialization is strictly read-only with respect
// to eFuse. The only method permitted to program eFuse is the explicitly named
// initialize_production_security(), which must be protected by higher-level Web
// and physical-device confirmation before it is called.
class HmacEfuseSecurityBackend final : public SecurityBackend {
public:
    explicit HmacEfuseSecurityBackend(std::uint8_t hmac_key_id);

    Status initialize_partition() override;
    Status verify_encryption_active() override;
    Status erase_user_partition() override;
    std::string_view profile() const override;
    bool production_release_allowed() const override;
    Status production_security_status(ProductionSecurityStatus* status) const override;
    Status initialize_production_security() override;

private:
    std::uint8_t hmac_key_id_;
    bool burn_attempted_{false};
};

class Store {
public:
    explicit Store(SecurityBackend& security_backend);

    Status initialize();
    bool ready() const;
    Status initialization_status() const;
    std::string_view security_profile() const;
    bool production_release_allowed() const;
    Status production_security_status(ProductionSecurityStatus* status) const;
    Status initialize_production_security();

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
