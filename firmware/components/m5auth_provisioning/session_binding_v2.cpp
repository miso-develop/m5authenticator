#include "m5auth/provisioning/session_protocol_v2.hpp"

#include <algorithm>

namespace m5auth::provisioning {
namespace {

template <typename Container>
bool all_zero(const Container& value) {
    return std::all_of(value.begin(), value.end(), [](std::uint8_t byte) { return byte == 0; });
}

template <typename Container>
bool same_bytes(const Container& left, const Container& right) {
    std::uint8_t diff = 0;
    for (std::size_t index = 0; index < left.size(); ++index) {
        diff |= static_cast<std::uint8_t>(left[index] ^ right[index]);
    }
    return diff == 0;
}

bool existing_vault_matches(
    const session::protocol_v2::BeginContext& context,
    const SessionV2DeviceSnapshot& snapshot
) {
    return snapshot.vault_present &&
        same_bytes(context.vault_id, snapshot.vault_id) &&
        context.expected_generation == snapshot.generation;
}

bool existing_registration_matches(
    const session::protocol_v2::BeginContext& context,
    const SessionV2DeviceSnapshot& snapshot
) {
    return snapshot.registration_present &&
        same_bytes(context.registration_id, snapshot.registration_id) &&
        context.registration_epoch == snapshot.registration_epoch;
}

bool current_brk_is_device_owned(
    const session::protocol_v2::BeginContext& context,
    const SessionV2DeviceSnapshot& snapshot,
    bool optional
) {
    if (!snapshot.registration_present || all_zero(snapshot.brk_public_key)) return false;
    if (all_zero(context.current_brk_public_key)) return optional;
    return same_bytes(context.current_brk_public_key, snapshot.brk_public_key);
}

bool clean_unprovisioned_snapshot(const SessionV2DeviceSnapshot& snapshot) {
    return !snapshot.vault_present &&
        snapshot.generation == 0 &&
        all_zero(snapshot.vault_id) &&
        !snapshot.registration_present &&
        snapshot.registration_epoch == 0 &&
        all_zero(snapshot.registration_id) &&
        all_zero(snapshot.brk_public_key);
}

}  // namespace

bool session_v2_begin_matches_snapshot(
    const session::protocol_v2::BeginContext& context,
    const SessionV2DeviceSnapshot& snapshot
) {
    if (snapshot.device_id.empty() || context.device_id != snapshot.device_id) return false;

    switch (context.operation) {
        case session::protocol_v2::Operation::kInitialProvisioning:
            return clean_unprovisioned_snapshot(snapshot) &&
                context.expected_generation == 0 &&
                all_zero(context.current_brk_public_key) &&
                !all_zero(context.proposed_brk_public_key);

        case session::protocol_v2::Operation::kTrustedBrowserUnlock:
        case session::protocol_v2::Operation::kVmkRekey:
            return existing_vault_matches(context, snapshot) &&
                existing_registration_matches(context, snapshot) &&
                current_brk_is_device_owned(context, snapshot, false) &&
                all_zero(context.proposed_brk_public_key);

        case session::protocol_v2::Operation::kRecovery:
        case session::protocol_v2::Operation::kBrowserReplacement:
            return existing_vault_matches(context, snapshot) &&
                existing_registration_matches(context, snapshot) &&
                current_brk_is_device_owned(context, snapshot, true) &&
                !all_zero(context.proposed_brk_public_key) &&
                !same_bytes(context.proposed_brk_public_key, snapshot.brk_public_key);
    }
    return false;
}

}  // namespace m5auth::provisioning
