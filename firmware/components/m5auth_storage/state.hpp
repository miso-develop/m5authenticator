#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "m5auth/storage/storage.hpp"

namespace m5auth::storage::internal {

struct AccountRecord {
    std::uint32_t id{0};
    std::uint16_t order{0};
    std::string issuer;
    std::string account;
    std::string display_name;
    std::string secret;
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
void secure_zero(void* data, std::size_t size);
void secure_clear_bytes(std::vector<std::uint8_t>* bytes);

}  // namespace m5auth::storage::internal
