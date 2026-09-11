#include <array>
#include <cassert>
#include <cstdint>

#include "m5auth/provisioning/session_protocol_v2.hpp"

namespace {

template <std::size_t N>
std::array<std::uint8_t, N> sequence(std::uint8_t start) {
    std::array<std::uint8_t, N> value{};
    for (std::size_t index = 0; index < N; ++index) {
        value[index] = static_cast<std::uint8_t>(start + index);
    }
    return value;
}

m5auth::session::protocol_v2::BrkPublicKey public_key(std::uint8_t start) {
    m5auth::session::protocol_v2::BrkPublicKey key{};
    key[0] = 0x04;
    for (std::size_t index = 1; index < key.size(); ++index) {
        key[index] = static_cast<std::uint8_t>(start + index - 1);
    }
    return key;
}

}  // namespace

int main() {
    using namespace m5auth::provisioning;
    using namespace m5auth::session::protocol_v2;

    SessionV2DeviceSnapshot snapshot{};
    snapshot.device_id = "stick3-test";
    snapshot.vault_present = true;
    snapshot.vault_id = sequence<kVaultIdBytes>(0x10);
    snapshot.generation = 7;
    snapshot.registration_present = true;
    snapshot.registration_id = sequence<kRegistrationIdBytes>(0x30);
    snapshot.registration_epoch = 4;
    snapshot.brk_public_key = public_key(0x50);

    BeginContext trusted{};
    trusted.operation = Operation::kTrustedBrowserUnlock;
    trusted.device_id = snapshot.device_id;
    trusted.vault_id = snapshot.vault_id;
    trusted.expected_generation = snapshot.generation;
    trusted.registration_id = snapshot.registration_id;
    trusted.registration_epoch = snapshot.registration_epoch;
    trusted.current_brk_public_key = snapshot.brk_public_key;
    assert(session_v2_begin_matches_snapshot(trusted, snapshot));

    BeginContext forged_brk = trusted;
    forged_brk.current_brk_public_key = public_key(0x70);
    assert(!session_v2_begin_matches_snapshot(forged_brk, snapshot));

    BeginContext stale_generation = trusted;
    stale_generation.expected_generation -= 1;
    assert(!session_v2_begin_matches_snapshot(stale_generation, snapshot));

    BeginContext stale_epoch = trusted;
    stale_epoch.registration_epoch -= 1;
    assert(!session_v2_begin_matches_snapshot(stale_epoch, snapshot));

    BeginContext hidden_replacement = trusted;
    hidden_replacement.proposed_brk_public_key = public_key(0x90);
    assert(!session_v2_begin_matches_snapshot(hidden_replacement, snapshot));

    BeginContext recovery = trusted;
    recovery.operation = Operation::kRecovery;
    recovery.registration_id = sequence<kRegistrationIdBytes>(0xa0);
    recovery.registration_epoch = snapshot.registration_epoch + 1;
    recovery.current_brk_public_key.fill(0);
    recovery.proposed_brk_public_key = public_key(0x90);
    assert(session_v2_begin_matches_snapshot(recovery, snapshot));

    BeginContext replacement = recovery;
    replacement.operation = Operation::kBrowserReplacement;
    replacement.current_brk_public_key = snapshot.brk_public_key;
    assert(session_v2_begin_matches_snapshot(replacement, snapshot));

    recovery.proposed_brk_public_key = snapshot.brk_public_key;
    assert(!session_v2_begin_matches_snapshot(recovery, snapshot));

    recovery.proposed_brk_public_key = public_key(0x90);
    recovery.registration_id = snapshot.registration_id;
    assert(!session_v2_begin_matches_snapshot(recovery, snapshot));

    recovery.registration_id = sequence<kRegistrationIdBytes>(0xa0);
    recovery.registration_epoch = snapshot.registration_epoch;
    assert(!session_v2_begin_matches_snapshot(recovery, snapshot));

    recovery.registration_epoch = snapshot.registration_epoch + 1;
    recovery.current_brk_public_key = public_key(0xb0);
    assert(!session_v2_begin_matches_snapshot(recovery, snapshot));

    SessionV2DeviceSnapshot empty{};
    empty.device_id = "stick3-test";
    BeginContext initial{};
    initial.operation = Operation::kInitialProvisioning;
    initial.device_id = empty.device_id;
    initial.vault_id = sequence<kVaultIdBytes>(0xa0);
    initial.expected_generation = 0;
    initial.registration_id = sequence<kRegistrationIdBytes>(0xb0);
    initial.registration_epoch = 0;
    initial.proposed_brk_public_key = public_key(0xc0);
    assert(session_v2_begin_matches_snapshot(initial, empty));

    initial.registration_id.fill(0);
    assert(!session_v2_begin_matches_snapshot(initial, empty));

    initial.registration_id = sequence<kRegistrationIdBytes>(0xb0);
    initial.expected_generation = 1;
    assert(!session_v2_begin_matches_snapshot(initial, empty));

    initial.expected_generation = 0;
    empty.registration_present = true;
    assert(!session_v2_begin_matches_snapshot(initial, empty));

    empty.registration_present = false;
    empty.generation = 1;
    assert(!session_v2_begin_matches_snapshot(initial, empty));

    empty.generation = 0;
    initial.device_id = "other-device";
    assert(!session_v2_begin_matches_snapshot(initial, empty));

    return 0;
}
