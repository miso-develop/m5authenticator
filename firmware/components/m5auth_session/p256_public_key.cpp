#include "m5auth/session/session.hpp"

#ifdef ESP_PLATFORM
#include "psa/crypto.h"
#else
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#endif

namespace m5auth::session {

bool valid_p256_public_key(std::span<const std::uint8_t> public_key) {
    if (public_key.size() != kP256PublicKeyBytes || public_key[0] != 0x04) return false;

#ifdef ESP_PLATFORM
    if (psa_crypto_init() != PSA_SUCCESS) return false;

    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attributes, PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&attributes, 256);
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_VERIFY_HASH);
    psa_set_key_algorithm(&attributes, PSA_ALG_ECDSA(PSA_ALG_SHA_256));

    psa_key_id_t key_id = 0;
    const psa_status_t status = psa_import_key(
        &attributes,
        public_key.data(), public_key.size(),
        &key_id
    );
    psa_reset_key_attributes(&attributes);
    if (status != PSA_SUCCESS) return false;
    (void)psa_destroy_key(key_id);
    return true;
#else
    EVP_PKEY_CTX* import_context = EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr);
    if (import_context == nullptr) return false;
    if (EVP_PKEY_fromdata_init(import_context) != 1) {
        EVP_PKEY_CTX_free(import_context);
        return false;
    }

    char group[] = "P-256";
    OSSL_PARAM parameters[] = {
        OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, group, 0),
        OSSL_PARAM_construct_octet_string(
            OSSL_PKEY_PARAM_PUB_KEY,
            const_cast<std::uint8_t*>(public_key.data()),
            public_key.size()
        ),
        OSSL_PARAM_construct_end(),
    };

    EVP_PKEY* key = nullptr;
    const bool imported = EVP_PKEY_fromdata(
        import_context,
        &key,
        EVP_PKEY_PUBLIC_KEY,
        parameters
    ) == 1 && key != nullptr;
    EVP_PKEY_CTX_free(import_context);
    if (!imported) {
        EVP_PKEY_free(key);
        return false;
    }

    EVP_PKEY_CTX* check_context = EVP_PKEY_CTX_new_from_pkey(nullptr, key, nullptr);
    const bool valid = check_context != nullptr &&
        EVP_PKEY_public_check(check_context) == 1;
    EVP_PKEY_CTX_free(check_context);
    EVP_PKEY_free(key);
    return valid;
#endif
}

}  // namespace m5auth::session
