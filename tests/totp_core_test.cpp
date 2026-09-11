#include <array>
#include <cassert>
#include <cstdint>
#include <cstring>
#include <string_view>

#include "m5auth/totp/totp.hpp"

namespace {
constexpr std::string_view kRfcSecretBase32 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
constexpr std::array<std::uint8_t, 20> kRfcSecretBytes{'1','2','3','4','5','6','7','8','9','0','1','2','3','4','5','6','7','8','9','0'};
struct Vector { std::uint64_t unix_seconds; std::array<std::uint8_t,20> digest; std::uint32_t expected; };
constexpr std::array<Vector, 6> kVectors{{
    {59ULL,{0x75,0xa4,0x8a,0x19,0xd4,0xcb,0xe1,0x00,0x64,0x4e,0x8a,0xc1,0x39,0x7e,0xea,0x74,0x7a,0x2d,0x33,0xab},287082},
    {1111111109ULL,{0x27,0x8c,0x02,0xe5,0x36,0x10,0xf8,0x4c,0x40,0xbd,0x91,0x35,0xac,0xd4,0x10,0x10,0x12,0x41,0x0a,0x14},81804},
    {1111111111ULL,{0xb0,0x09,0x2b,0x21,0xd0,0x48,0xaf,0x20,0x9d,0xa0,0xa1,0xdd,0xd4,0x98,0xad,0xe8,0xa7,0x94,0x87,0xed},50471},
    {1234567890ULL,{0x90,0x7c,0xd1,0xa9,0x11,0x65,0x64,0xec,0xb9,0xd5,0xd1,0x78,0x03,0x25,0xf2,0x46,0x17,0x3f,0xe7,0x03},5924},
    {2000000000ULL,{0x25,0xa3,0x26,0xd3,0x1f,0xc3,0x66,0x24,0x4c,0xad,0x05,0x49,0x76,0x02,0x0c,0x7b,0x56,0xb1,0x3d,0x5f},279037},
    {20000000000ULL,{0xab,0x07,0xe9,0x7e,0x2c,0x12,0x78,0x76,0x9d,0xbc,0xd7,0x57,0x83,0xaa,0xbd,0xe7,0x5e,0xd8,0x55,0x0a},353130}
}};

std::uint64_t decode_counter(const std::uint8_t* message) {
    std::uint64_t value = 0;
    for (int i = 0; i < 8; ++i) value = (value << 8U) | message[i];
    return value;
}

bool rfc_provider(const std::uint8_t* key, std::size_t key_size, const std::uint8_t* message,
                  std::size_t message_size, std::uint8_t output[20]) {
    if (key == nullptr || message == nullptr || output == nullptr || key_size != kRfcSecretBytes.size() ||
        message_size != 8 || std::memcmp(key, kRfcSecretBytes.data(), kRfcSecretBytes.size()) != 0) return false;
    const std::uint64_t counter = decode_counter(message);
    for (const auto& vector : kVectors) {
        if (vector.unix_seconds / m5auth::totp::kPeriodSeconds == counter) {
            std::memcpy(output, vector.digest.data(), vector.digest.size());
            return true;
        }
    }
    return false;
}

void matches_vectors() {
    for (const auto& vector : kVectors) {
        std::uint32_t base32_code = 0;
        assert(m5auth::totp::generate_with_provider(
            kRfcSecretBase32,
            vector.unix_seconds,
            &rfc_provider,
            &base32_code
        ) == m5auth::totp::CoreResult::kOk);
        assert(base32_code == vector.expected);

        std::uint32_t raw_code = 0;
        assert(m5auth::totp::generate_raw_with_provider(
            kRfcSecretBytes,
            vector.unix_seconds,
            &rfc_provider,
            &raw_code
        ) == m5auth::totp::CoreResult::kOk);
        assert(raw_code == vector.expected);
    }
}

void rejects_invalid_secret() {
    std::uint32_t code = 0;
    assert(m5auth::totp::generate_with_provider(
        "NOT-BASE32!",
        59,
        &rfc_provider,
        &code
    ) == m5auth::totp::CoreResult::kInvalidSecret);
    assert(m5auth::totp::generate_raw_with_provider(
        {},
        59,
        &rfc_provider,
        &code
    ) == m5auth::totp::CoreResult::kInvalidSecret);
}
}

int main() { matches_vectors(); rejects_invalid_secret(); return 0; }
