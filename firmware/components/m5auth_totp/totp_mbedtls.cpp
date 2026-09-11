#include "m5auth/totp/totp.hpp"

#include "mbedtls/md.h"

namespace m5auth::totp {
namespace {

bool hmac_sha1(
    const std::uint8_t* key,
    std::size_t key_size,
    const std::uint8_t* message,
    std::size_t message_size,
    std::uint8_t output[20]
) {
    if (key == nullptr || message == nullptr || output == nullptr) return false;
    const mbedtls_md_info_t* info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA1);
    if (info == nullptr) return false;
    return mbedtls_md_hmac(info, key, key_size, message, message_size, output) == 0;
}

}  // namespace

CoreResult generate_raw(
    std::span<const std::uint8_t> secret,
    std::uint64_t unix_seconds,
    std::uint32_t* code
) {
    return generate_raw_with_provider(secret, unix_seconds, &hmac_sha1, code);
}

CoreResult generate(
    std::string_view base32_secret,
    std::uint64_t unix_seconds,
    std::uint32_t* code
) {
    return generate_with_provider(base32_secret, unix_seconds, &hmac_sha1, code);
}

}  // namespace m5auth::totp
