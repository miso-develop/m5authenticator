#include <array>
#include <cassert>
#include <cstdint>
#include <string>
#include <vector>

#include "m5auth/session/protocol_v2.hpp"

namespace {

template <std::size_t N>
std::array<std::uint8_t, N> sequence(std::uint8_t start) {
    std::array<std::uint8_t, N> out{};
    for (std::size_t i = 0; i < N; ++i) out[i] = static_cast<std::uint8_t>(start + i);
    return out;
}

m5auth::session::P256PublicKey public_key(std::uint8_t start) {
    m5auth::session::P256PublicKey out{};
    out[0] = 0x04;
    for (std::size_t i = 1; i < out.size(); ++i) out[i] = static_cast<std::uint8_t>(start + i - 1);
    return out;
}

std::string hex(const std::vector<std::uint8_t>& bytes) {
    constexpr char digits[] = "0123456789abcdef";
    std::string out;
    out.reserve(bytes.size() * 2);
    for (std::uint8_t value : bytes) {
        out.push_back(digits[value >> 4]);
        out.push_back(digits[value & 0x0f]);
    }
    return out;
}

}  // namespace

int main() {
    using namespace m5auth::session;
    using namespace m5auth::session::protocol_v2;

    TranscriptInput input{};
    input.operation = Operation::kTrustedBrowserUnlock;
    input.device_id = "stick3-test";
    input.vault_id = sequence<kVaultIdBytes>(0x00);
    input.expected_generation = 0x0102030405060708ULL;
    input.registration_id = sequence<kRegistrationIdBytes>(0x10);
    input.registration_epoch = 0x01020304U;
    input.attempt_id = sequence<kAttemptIdBytes>(0x20);
    input.challenge = sequence<kDeviceChallengeBytes>(0x30);
    input.device_ephemeral_public_key = public_key(0x01);
    input.web_ephemeral_public_key = public_key(0x41);
    input.current_brk_public_key = public_key(0x81);

    std::vector<std::uint8_t> transcript;
    assert(encode_transcript(input, &transcript));
    assert(transcript.size() == 371);
    const std::string expected =
        "4d3541530102010b737469636b332d74657374000102030405060708090a0b0c0d0e0f"
        "0102030405060708101112131415161718191a1b1c1d1e1f010203042021222324252627"
        "28292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a"
        "4b4c4d4e4f040102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d"
        "1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40"
        "044142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162"
        "636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f800481828384"
        "85868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6"
        "a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc00000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000";
    assert(hex(transcript) == expected);

    const std::string encoded = base64url_encode(transcript);
    std::vector<std::uint8_t> decoded;
    assert(base64url_decode(encoded, &decoded));
    assert(decoded == transcript);
    assert(!base64url_decode(encoded + "=", &decoded));
    assert(!base64url_decode("A", &decoded));

    TranscriptInput initial = input;
    initial.operation = Operation::kInitialProvisioning;
    initial.registration_id.fill(0);
    initial.registration_epoch = 0;
    initial.current_brk_public_key.fill(0);
    initial.proposed_brk_public_key = public_key(0xc1);
    assert(encode_transcript(initial, &transcript));

    initial.proposed_brk_public_key.fill(0);
    assert(!encode_transcript(initial, &transcript));

    Operation parsed{};
    assert(parse_operation("browser_replacement", &parsed));
    assert(parsed == Operation::kBrowserReplacement);
    assert(!parse_operation("unlock", &parsed));
    return 0;
}
