#include "m5auth/totp/totp.hpp"

#include <array>
#include <vector>

namespace m5auth::totp {
namespace {

void secure_zero(void* data, std::size_t size) {
    volatile auto* cursor = static_cast<volatile std::uint8_t*>(data);
    while (size-- > 0) {
        *cursor++ = 0;
    }
}

int base32_value(char ch) {
    if (ch >= 'A' && ch <= 'Z') return ch - 'A';
    if (ch >= 'a' && ch <= 'z') return ch - 'a';
    if (ch >= '2' && ch <= '7') return 26 + (ch - '2');
    return -1;
}

bool decode_base32(std::string_view encoded, std::vector<std::uint8_t>* decoded) {
    if (decoded == nullptr || encoded.empty()) return false;
    decoded->clear();
    decoded->reserve((encoded.size() * 5U + 7U) / 8U);
    std::uint32_t accumulator = 0;
    int bits = 0;
    bool padding_started = false;
    for (char ch : encoded) {
        if (ch == '=') {
            padding_started = true;
            continue;
        }
        if (padding_started) return false;
        const int value = base32_value(ch);
        if (value < 0) return false;
        accumulator = (accumulator << 5U) | static_cast<std::uint32_t>(value);
        bits += 5;
        if (bits >= 8) {
            bits -= 8;
            decoded->push_back(static_cast<std::uint8_t>((accumulator >> bits) & 0xffU));
        }
    }
    if (decoded->empty()) return false;
    if (bits > 0) {
        const std::uint32_t mask = (1U << bits) - 1U;
        if ((accumulator & mask) != 0) return false;
    }
    return true;
}

void clear_bytes(std::vector<std::uint8_t>* bytes) {
    if (bytes != nullptr && !bytes->empty()) {
        secure_zero(bytes->data(), bytes->size());
        bytes->clear();
    }
}

}  // namespace

CoreResult generate_with_provider(
    std::string_view base32_secret,
    std::uint64_t unix_seconds,
    HmacSha1Provider provider,
    std::uint32_t* code
) {
    if (provider == nullptr || code == nullptr) return CoreResult::kCryptoError;
    std::vector<std::uint8_t> key;
    if (!decode_base32(base32_secret, &key)) {
        clear_bytes(&key);
        return CoreResult::kInvalidSecret;
    }
    const std::uint64_t counter = unix_seconds / kPeriodSeconds;
    std::array<std::uint8_t, 8> message{};
    for (std::size_t index = 0; index < message.size(); ++index) {
        const unsigned shift = static_cast<unsigned>((7U - index) * 8U);
        message[index] = static_cast<std::uint8_t>((counter >> shift) & 0xffU);
    }
    std::array<std::uint8_t, 20> digest{};
    const bool hmac_ok = provider(key.data(), key.size(), message.data(), message.size(), digest.data());
    clear_bytes(&key);
    secure_zero(message.data(), message.size());
    if (!hmac_ok) {
        secure_zero(digest.data(), digest.size());
        return CoreResult::kCryptoError;
    }
    const std::size_t offset = digest.back() & 0x0fU;
    if (offset + 3U >= digest.size()) {
        secure_zero(digest.data(), digest.size());
        return CoreResult::kCryptoError;
    }
    const std::uint32_t binary =
        (static_cast<std::uint32_t>(digest[offset] & 0x7fU) << 24U) |
        (static_cast<std::uint32_t>(digest[offset + 1]) << 16U) |
        (static_cast<std::uint32_t>(digest[offset + 2]) << 8U) |
        static_cast<std::uint32_t>(digest[offset + 3]);
    *code = binary % kModulo;
    secure_zero(digest.data(), digest.size());
    return CoreResult::kOk;
}

}  // namespace m5auth::totp
