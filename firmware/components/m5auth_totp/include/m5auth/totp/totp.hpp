#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

namespace m5auth::totp {

inline constexpr std::uint32_t kPeriodSeconds = 30;
inline constexpr std::uint32_t kDigits = 6;
inline constexpr std::uint32_t kModulo = 1'000'000;

enum class CoreResult {
    kOk,
    kInvalidSecret,
    kCryptoError,
};

using HmacSha1Provider = bool (*)(
    const std::uint8_t* key,
    std::size_t key_size,
    const std::uint8_t* message,
    std::size_t message_size,
    std::uint8_t output[20]
);

CoreResult generate_raw_with_provider(
    std::span<const std::uint8_t> secret,
    std::uint64_t unix_seconds,
    HmacSha1Provider provider,
    std::uint32_t* code
);

CoreResult generate_with_provider(
    std::string_view base32_secret,
    std::uint64_t unix_seconds,
    HmacSha1Provider provider,
    std::uint32_t* code
);

CoreResult generate_raw(
    std::span<const std::uint8_t> secret,
    std::uint64_t unix_seconds,
    std::uint32_t* code
);

CoreResult generate(
    std::string_view base32_secret,
    std::uint64_t unix_seconds,
    std::uint32_t* code
);

}  // namespace m5auth::totp
