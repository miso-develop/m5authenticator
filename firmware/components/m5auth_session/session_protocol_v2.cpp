#include "m5auth/session/protocol_v2.hpp"

#include <algorithm>
#include <limits>

namespace m5auth::session::protocol_v2 {
namespace {

constexpr char kAlphabet[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

void append_u32(std::vector<std::uint8_t>& out, std::uint32_t value) {
    out.push_back(static_cast<std::uint8_t>((value >> 24) & 0xff));
    out.push_back(static_cast<std::uint8_t>((value >> 16) & 0xff));
    out.push_back(static_cast<std::uint8_t>((value >> 8) & 0xff));
    out.push_back(static_cast<std::uint8_t>(value & 0xff));
}

void append_u64(std::vector<std::uint8_t>& out, std::uint64_t value) {
    for (int shift = 56; shift >= 0; shift -= 8) {
        out.push_back(static_cast<std::uint8_t>((value >> shift) & 0xff));
    }
}

template <std::size_t N>
void append_array(std::vector<std::uint8_t>& out, const std::array<std::uint8_t, N>& value) {
    out.insert(out.end(), value.begin(), value.end());
}

int decode_char(char value) {
    if (value >= 'A' && value <= 'Z') return value - 'A';
    if (value >= 'a' && value <= 'z') return value - 'a' + 26;
    if (value >= '0' && value <= '9') return value - '0' + 52;
    if (value == '-') return 62;
    if (value == '_') return 63;
    return -1;
}

}  // namespace

const char* operation_name(Operation operation) {
    switch (operation) {
        case Operation::kTrustedBrowserUnlock: return "trusted_browser_unlock";
        case Operation::kInitialProvisioning: return "initial_provisioning";
        case Operation::kRecovery: return "recovery";
        case Operation::kBrowserReplacement: return "browser_replacement";
        case Operation::kVmkRekey: return "vmk_rekey";
    }
    return "invalid";
}

bool parse_operation(std::string_view value, Operation* operation) {
    if (operation == nullptr) return false;
    if (value == "trusted_browser_unlock") *operation = Operation::kTrustedBrowserUnlock;
    else if (value == "initial_provisioning") *operation = Operation::kInitialProvisioning;
    else if (value == "recovery") *operation = Operation::kRecovery;
    else if (value == "browser_replacement") *operation = Operation::kBrowserReplacement;
    else if (value == "vmk_rekey") *operation = Operation::kVmkRekey;
    else return false;
    return true;
}

PresenceOperation presence_operation(Operation operation) {
    switch (operation) {
        case Operation::kTrustedBrowserUnlock: return PresenceOperation::kTrustedBrowserUnlock;
        case Operation::kInitialProvisioning: return PresenceOperation::kInitialProvisioning;
        case Operation::kRecovery: return PresenceOperation::kRecovery;
        case Operation::kBrowserReplacement: return PresenceOperation::kBrowserReplacement;
        case Operation::kVmkRekey: return PresenceOperation::kVmkRekey;
    }
    return PresenceOperation::kTrustedBrowserUnlock;
}

bool is_zero_public_key(const P256PublicKey& key) {
    return std::all_of(key.begin(), key.end(), [](std::uint8_t value) { return value == 0; });
}

bool valid_optional_p256_identity(const P256PublicKey& key) {
    return is_zero_public_key(key) || key[0] == 0x04;
}

bool encode_transcript(const TranscriptInput& input, std::vector<std::uint8_t>* output) {
    if (output == nullptr || input.device_id.empty() || input.device_id.size() > kMaxDeviceIdBytes) return false;
    if (input.device_ephemeral_public_key[0] != 0x04 || input.web_ephemeral_public_key[0] != 0x04) return false;
    if (!valid_optional_p256_identity(input.current_brk_public_key) ||
        !valid_optional_p256_identity(input.proposed_brk_public_key)) return false;

    switch (input.operation) {
        case Operation::kTrustedBrowserUnlock:
            if (is_zero_public_key(input.current_brk_public_key) || input.registration_epoch == 0) return false;
            break;
        case Operation::kInitialProvisioning:
            if (!is_zero_public_key(input.current_brk_public_key) ||
                is_zero_public_key(input.proposed_brk_public_key) || input.registration_epoch != 0) return false;
            break;
        case Operation::kRecovery:
        case Operation::kBrowserReplacement:
            if (is_zero_public_key(input.proposed_brk_public_key)) return false;
            break;
        case Operation::kVmkRekey:
            if (is_zero_public_key(input.current_brk_public_key) || input.registration_epoch == 0) return false;
            break;
        default:
            return false;
    }

    output->clear();
    output->reserve(kTranscriptFixedBytes + input.device_id.size());
    output->insert(output->end(), {'M', '5', 'A', 'S'});
    output->push_back(kTranscriptVersion);
    output->push_back(kProtocolVersion);
    output->push_back(static_cast<std::uint8_t>(input.operation));
    output->push_back(static_cast<std::uint8_t>(input.device_id.size()));
    output->insert(output->end(), input.device_id.begin(), input.device_id.end());
    append_array(*output, input.vault_id);
    append_u64(*output, input.expected_generation);
    append_array(*output, input.registration_id);
    append_u32(*output, input.registration_epoch);
    append_array(*output, input.attempt_id);
    append_array(*output, input.challenge);
    append_array(*output, input.device_ephemeral_public_key);
    append_array(*output, input.web_ephemeral_public_key);
    append_array(*output, input.current_brk_public_key);
    append_array(*output, input.proposed_brk_public_key);
    return output->size() == kTranscriptFixedBytes + input.device_id.size();
}

std::string base64url_encode(std::span<const std::uint8_t> value) {
    std::string out;
    out.reserve((value.size() * 4 + 2) / 3);
    std::size_t index = 0;
    while (index + 3 <= value.size()) {
        const std::uint32_t bits = (static_cast<std::uint32_t>(value[index]) << 16) |
            (static_cast<std::uint32_t>(value[index + 1]) << 8) | value[index + 2];
        out.push_back(kAlphabet[(bits >> 18) & 0x3f]);
        out.push_back(kAlphabet[(bits >> 12) & 0x3f]);
        out.push_back(kAlphabet[(bits >> 6) & 0x3f]);
        out.push_back(kAlphabet[bits & 0x3f]);
        index += 3;
    }
    const std::size_t remaining = value.size() - index;
    if (remaining == 1) {
        const std::uint32_t bits = static_cast<std::uint32_t>(value[index]) << 16;
        out.push_back(kAlphabet[(bits >> 18) & 0x3f]);
        out.push_back(kAlphabet[(bits >> 12) & 0x3f]);
    } else if (remaining == 2) {
        const std::uint32_t bits = (static_cast<std::uint32_t>(value[index]) << 16) |
            (static_cast<std::uint32_t>(value[index + 1]) << 8);
        out.push_back(kAlphabet[(bits >> 18) & 0x3f]);
        out.push_back(kAlphabet[(bits >> 12) & 0x3f]);
        out.push_back(kAlphabet[(bits >> 6) & 0x3f]);
    }
    return out;
}

bool base64url_decode(std::string_view value, std::vector<std::uint8_t>* output) {
    if (output == nullptr || value.size() % 4 == 1) return false;
    output->clear();
    output->reserve(value.size() * 3 / 4 + 2);

    std::uint32_t accumulator = 0;
    int bits = 0;
    for (char ch : value) {
        const int decoded = decode_char(ch);
        if (decoded < 0) {
            output->clear();
            return false;
        }
        accumulator = (accumulator << 6) | static_cast<std::uint32_t>(decoded);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            output->push_back(static_cast<std::uint8_t>((accumulator >> bits) & 0xff));
        }
    }
    if (bits > 0) {
        const std::uint32_t mask = (1u << bits) - 1u;
        if ((accumulator & mask) != 0) {
            output->clear();
            return false;
        }
    }
    if (base64url_encode(*output) != value) {
        output->clear();
        return false;
    }
    return true;
}

}  // namespace m5auth::session::protocol_v2
