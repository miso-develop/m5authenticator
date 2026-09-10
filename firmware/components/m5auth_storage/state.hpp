#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "m5auth/storage/storage.hpp"

namespace m5auth::storage::internal {

void secure_zero(void* data, std::size_t size);
void secure_clear(std::string* value);
void secure_clear_bytes(std::vector<std::uint8_t>* bytes);

// Internal string for stored secret material. Its copy/move/destruction semantics
// wipe the previous/source value so vector relocation and erase/sort operations
// do not leave short-string secret bytes in abandoned objects.
class SensitiveString final : public std::string {
public:
    using std::string::string;

    SensitiveString() = default;
    SensitiveString(const std::string& other);
    SensitiveString(std::string&& other) noexcept;
    SensitiveString(const SensitiveString& other);
    SensitiveString(SensitiveString&& other) noexcept;
    SensitiveString& operator=(const std::string& other);
    SensitiveString& operator=(std::string&& other) noexcept;
    SensitiveString& operator=(const SensitiveString& other);
    SensitiveString& operator=(SensitiveString&& other) noexcept;
    ~SensitiveString();
};

struct AccountRecord {
    std::uint32_t id{0};
    std::uint16_t order{0};
    std::string issuer;
    std::string account;
    std::string display_name;
    SensitiveString secret;
};

struct State {
    std::uint32_t next_id{1};
    std::uint32_t last_used_id{0};
    std::string wifi_ssid;
    std::string wifi_password;
    std::vector<AccountRecord> accounts;
};

Status validate_account_draft(const AccountDraft& draft);
Status validate_state(const State& state);
Status encode_state(const State& state, std::vector<std::uint8_t>* output);
Status decode_state(const std::uint8_t* data, std::size_t size, State* output);
void wipe_state(State* state);

}  // namespace m5auth::storage::internal
