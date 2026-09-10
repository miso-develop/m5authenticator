#include <cassert>
#include <cstdint>
#include <string>
#include <vector>

#include "state.hpp"

using m5auth::storage::Status;
using m5auth::storage::internal::AccountRecord;
using m5auth::storage::internal::State;

namespace {

AccountRecord synthetic_record(std::uint32_t id, std::uint16_t order) {
    AccountRecord record;
    record.id = id;
    record.order = order;
    record.issuer = "Synthetic Issuer";
    record.account = "example-user";
    record.display_name = "Test Account";
    record.secret.resize(20, 'x');
    return record;
}

void round_trip_preserves_state() {
    State state;
    state.next_id = 3;
    state.last_used_id = 2;
    state.wifi_ssid = "synthetic-network";
    state.wifi_password.resize(16, 'p');
    state.accounts.push_back(synthetic_record(1, 0));
    state.accounts.push_back(synthetic_record(2, 1));

    std::vector<std::uint8_t> encoded;
    assert(m5auth::storage::internal::encode_state(state, &encoded) == Status::kOk);

    State decoded;
    assert(m5auth::storage::internal::decode_state(encoded.data(), encoded.size(), &decoded) == Status::kOk);
    assert(decoded.accounts.size() == 2);
    assert(decoded.accounts[1].id == 2);
    assert(decoded.accounts[1].order == 1);
    assert(decoded.last_used_id == 2);
    assert(decoded.wifi_ssid == "synthetic-network");
    assert(decoded.wifi_password.size() == 16);

    m5auth::storage::internal::wipe_state(&state);
    m5auth::storage::internal::wipe_state(&decoded);
    m5auth::storage::internal::secure_clear_bytes(&encoded);
}

void rejects_more_than_32_accounts() {
    State state;
    state.next_id = 40;
    for (std::uint16_t i = 0; i < 33; ++i) {
        state.accounts.push_back(synthetic_record(i + 1, i));
    }
    assert(m5auth::storage::internal::validate_state(state) == Status::kCorrupt);
    m5auth::storage::internal::wipe_state(&state);
}

void rejects_unknown_snapshot_format() {
    State state;
    state.accounts.push_back(synthetic_record(1, 0));
    state.next_id = 2;
    std::vector<std::uint8_t> encoded;
    assert(m5auth::storage::internal::encode_state(state, &encoded) == Status::kOk);
    encoded[4] = 2;

    State decoded;
    assert(m5auth::storage::internal::decode_state(encoded.data(), encoded.size(), &decoded) == Status::kCorrupt);
    m5auth::storage::internal::wipe_state(&state);
    m5auth::storage::internal::secure_clear_bytes(&encoded);
}

void rejects_duplicate_order() {
    State state;
    state.next_id = 3;
    state.accounts.push_back(synthetic_record(1, 0));
    state.accounts.push_back(synthetic_record(2, 0));
    assert(m5auth::storage::internal::validate_state(state) == Status::kCorrupt);
    m5auth::storage::internal::wipe_state(&state);
}

}  // namespace

int main() {
    round_trip_preserves_state();
    rejects_more_than_32_accounts();
    rejects_unknown_snapshot_format();
    rejects_duplicate_order();
    return 0;
}
