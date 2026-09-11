#include "m5auth/session/session.hpp"

#include <algorithm>
#include <array>
#include <climits>
#include <limits>
#include <vector>

#ifdef ESP_PLATFORM
#include "esp_random.h"
#include "mbedtls/gcm.h"
#include "mbedtls/hkdf.h"
#include "mbedtls/md.h"
#include "psa/crypto.h"
#else
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <openssl/rand.h>
#endif

namespace m5auth::session {
namespace {

void secure_zero(void* data, std::size_t size) {
    volatile auto* cursor = static_cast<volatile std::uint8_t*>(data);
    while (size-- > 0) *cursor++ = 0;
}

template <std::size_t N>
void clear_array(std::array<std::uint8_t, N>& value) {
    secure_zero(value.data(), value.size());
}

bool bounded_nonempty(std::span<const std::uint8_t> value, std::size_t maximum) {
    return !value.empty() && value.size() <= maximum;
}

bool constant_time_equal(
    std::span<const std::uint8_t> left,
    std::span<const std::uint8_t> right
) {
    if (left.size() != right.size()) return false;
    std::uint8_t difference = 0;
    for (std::size_t index = 0; index < left.size(); ++index) {
        difference |= static_cast<std::uint8_t>(left[index] ^ right[index]);
    }
    return difference == 0;
}

bool fill_random(std::span<std::uint8_t> output) {
#ifdef ESP_PLATFORM
    esp_fill_random(output.data(), output.size());
    return true;
#else
    return output.size() <= static_cast<std::size_t>(INT_MAX) &&
           RAND_bytes(output.data(), static_cast<int>(output.size())) == 1;
#endif
}

std::uint64_t deadline_from(std::uint64_t now_ms) {
    return now_ms > std::numeric_limits<std::uint64_t>::max() - kAttemptTtlMs
        ? std::numeric_limits<std::uint64_t>::max()
        : now_ms + kAttemptTtlMs;
}

#ifdef ESP_PLATFORM

bool derive_hkdf(
    std::span<const std::uint8_t> shared_secret,
    std::span<const std::uint8_t> salt,
    std::span<const std::uint8_t> info,
    std::array<std::uint8_t, kSessionKeyBytes>& session_key
) {
    const mbedtls_md_info_t* md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (md == nullptr) return false;
    return mbedtls_hkdf(
        md,
        salt.data(), salt.size(),
        shared_secret.data(), shared_secret.size(),
        info.data(), info.size(),
        session_key.data(), session_key.size()
    ) == 0;
}

bool decrypt_vmk_gcm(
    const std::array<std::uint8_t, kSessionKeyBytes>& session_key,
    std::span<const std::uint8_t> nonce,
    std::span<const std::uint8_t> ciphertext,
    std::span<const std::uint8_t> tag,
    std::span<const std::uint8_t> aad,
    Vmk& vmk
) {
    mbedtls_gcm_context context;
    mbedtls_gcm_init(&context);
    const bool ok =
        mbedtls_gcm_setkey(
            &context,
            MBEDTLS_CIPHER_ID_AES,
            session_key.data(),
            256
        ) == 0 &&
        mbedtls_gcm_auth_decrypt(
            &context,
            ciphertext.size(),
            nonce.data(), nonce.size(),
            aad.data(), aad.size(),
            tag.data(), tag.size(),
            ciphertext.data(),
            vmk.data()
        ) == 0;
    mbedtls_gcm_free(&context);
    if (!ok) clear_array(vmk);
    return ok;
}

bool verify_brk(
    std::span<const std::uint8_t> public_key,
    std::span<const std::uint8_t> transcript,
    std::span<const std::uint8_t> signature
) {
    if (psa_crypto_init() != PSA_SUCCESS) return false;

    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(
        &attributes,
        PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1)
    );
    psa_set_key_bits(&attributes, 256);
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_VERIFY_HASH);
    psa_set_key_algorithm(&attributes, PSA_ALG_ECDSA(PSA_ALG_SHA_256));

    psa_key_id_t key_id = 0;
    const psa_status_t import_status = psa_import_key(
        &attributes,
        public_key.data(), public_key.size(),
        &key_id
    );
    psa_reset_key_attributes(&attributes);
    if (import_status != PSA_SUCCESS) return false;

    std::array<std::uint8_t, 32> digest{};
    std::size_t digest_length = 0;
    const psa_status_t hash_status = psa_hash_compute(
        PSA_ALG_SHA_256,
        transcript.data(), transcript.size(),
        digest.data(), digest.size(),
        &digest_length
    );
    const psa_status_t verify_status = hash_status == PSA_SUCCESS && digest_length == digest.size()
        ? psa_verify_hash(
            key_id,
            PSA_ALG_ECDSA(PSA_ALG_SHA_256),
            digest.data(), digest.size(),
            signature.data(), signature.size()
        )
        : PSA_ERROR_INVALID_ARGUMENT;
    clear_array(digest);
    (void)psa_destroy_key(key_id);
    return verify_status == PSA_SUCCESS;
}

#else

bool generate_native_key(EVP_PKEY*& key, P256PublicKey& public_key) {
    EVP_PKEY_CTX* context = EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr);
    if (context == nullptr) return false;

    bool ok = EVP_PKEY_keygen_init(context) == 1 &&
              EVP_PKEY_CTX_set_group_name(context, "P-256") == 1 &&
              EVP_PKEY_generate(context, &key) == 1;
    EVP_PKEY_CTX_free(context);
    if (!ok || key == nullptr) return false;

    std::size_t length = 0;
    ok = EVP_PKEY_get_octet_string_param(
        key,
        OSSL_PKEY_PARAM_PUB_KEY,
        public_key.data(), public_key.size(),
        &length
    ) == 1 && length == public_key.size() && public_key[0] == 0x04;
    if (!ok) {
        EVP_PKEY_free(key);
        key = nullptr;
        clear_array(public_key);
    }
    return ok;
}

EVP_PKEY* import_native_public(std::span<const std::uint8_t> public_key) {
    EVP_PKEY_CTX* context = EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr);
    if (context == nullptr) return nullptr;
    if (EVP_PKEY_fromdata_init(context) != 1) {
        EVP_PKEY_CTX_free(context);
        return nullptr;
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
    const bool ok = EVP_PKEY_fromdata(
        context,
        &key,
        EVP_PKEY_PUBLIC_KEY,
        parameters
    ) == 1;
    EVP_PKEY_CTX_free(context);
    return ok ? key : nullptr;
}

bool derive_native_shared(
    EVP_PKEY* private_key,
    std::span<const std::uint8_t> peer_public_key,
    std::array<std::uint8_t, kSessionKeyBytes>& shared_secret
) {
    EVP_PKEY* peer = import_native_public(peer_public_key);
    if (peer == nullptr) return false;

    EVP_PKEY_CTX* context = EVP_PKEY_CTX_new_from_pkey(nullptr, private_key, nullptr);
    if (context == nullptr) {
        EVP_PKEY_free(peer);
        return false;
    }

    std::size_t length = shared_secret.size();
    const bool ok = EVP_PKEY_derive_init(context) == 1 &&
                    EVP_PKEY_derive_set_peer(context, peer) == 1 &&
                    EVP_PKEY_derive(context, shared_secret.data(), &length) == 1 &&
                    length == shared_secret.size();
    EVP_PKEY_CTX_free(context);
    EVP_PKEY_free(peer);
    if (!ok) clear_array(shared_secret);
    return ok;
}

bool derive_hkdf(
    std::span<const std::uint8_t> shared_secret,
    std::span<const std::uint8_t> salt,
    std::span<const std::uint8_t> info,
    std::array<std::uint8_t, kSessionKeyBytes>& session_key
) {
    if (shared_secret.size() > static_cast<std::size_t>(INT_MAX) ||
        salt.size() > static_cast<std::size_t>(INT_MAX) ||
        info.size() > static_cast<std::size_t>(INT_MAX)) {
        return false;
    }

    EVP_PKEY_CTX* context = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
    if (context == nullptr) return false;
    std::size_t length = session_key.size();
    const bool ok = EVP_PKEY_derive_init(context) == 1 &&
        EVP_PKEY_CTX_hkdf_mode(context, EVP_PKEY_HKDEF_MODE_EXTRACT_AND_EXPAND) == 1 &&
        EVP_PKEY_CTX_set_hkdf_md(context, EVP_sha256()) == 1 &&
        EVP_PKEY_CTX_set1_hkdf_salt(
            context,
            salt.data(), static_cast<int>(salt.size())
        ) == 1 &&
        EVP_PKEY_CTX_set1_hkdf_key(
            context,
            shared_secret.data(), static_cast<int>(shared_secret.size())
        ) == 1 &&
        EVP_PKEY_CTX_add1_hkdf_info(
            context,
            info.data(), static_cast<int>(info.size())
        ) == 1 &&
        EVP_PKEY_derive(context, session_key.data(), &length) == 1 &&
        length == session_key.size();
    EVP_PKEY_CTX_free(context);
    if (!ok) clear_array(session_key);
    return ok;
}

bool decrypt_vmk_gcm(
    const std::array<std::uint8_t, kSessionKeyBytes>& session_key,
    std::span<const std::uint8_t> nonce,
    std::span<const std::uint8_t> ciphertext,
    std::span<const std::uint8_t> tag,
    std::span<const std::uint8_t> aad,
    Vmk& vmk
) {
    if (aad.size() > static_cast<std::size_t>(INT_MAX)) return false;
    EVP_CIPHER_CTX* context = EVP_CIPHER_CTX_new();
    if (context == nullptr) return false;

    int written = 0;
    int total = 0;
    bool ok = EVP_DecryptInit_ex(context, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1 &&
        EVP_CIPHER_CTX_ctrl(
            context,
            EVP_CTRL_GCM_SET_IVLEN,
            static_cast<int>(nonce.size()),
            nullptr
        ) == 1 &&
        EVP_DecryptInit_ex(
            context,
            nullptr,
            nullptr,
            session_key.data(),
            nonce.data()
        ) == 1 &&
        EVP_DecryptUpdate(
            context,
            nullptr,
            &written,
            aad.data(),
            static_cast<int>(aad.size())
        ) == 1 &&
        EVP_DecryptUpdate(
            context,
            vmk.data(),
            &written,
            ciphertext.data(),
            static_cast<int>(ciphertext.size())
        ) == 1;
    total = written;
    if (ok) {
        ok = EVP_CIPHER_CTX_ctrl(
            context,
            EVP_CTRL_GCM_SET_TAG,
            static_cast<int>(tag.size()),
            const_cast<std::uint8_t*>(tag.data())
        ) == 1;
    }
    if (ok) {
        ok = EVP_DecryptFinal_ex(context, vmk.data() + total, &written) == 1;
        total += written;
    }
    EVP_CIPHER_CTX_free(context);
    if (!ok || total != static_cast<int>(vmk.size())) {
        clear_array(vmk);
        return false;
    }
    return true;
}

bool raw_signature_to_der(
    std::span<const std::uint8_t> signature,
    std::vector<std::uint8_t>& der
) {
    if (signature.size() != kBrkSignatureBytes) return false;
    BIGNUM* r = BN_bin2bn(signature.data(), 32, nullptr);
    BIGNUM* s = BN_bin2bn(signature.data() + 32, 32, nullptr);
    ECDSA_SIG* ecdsa = ECDSA_SIG_new();
    if (r == nullptr || s == nullptr || ecdsa == nullptr) {
        BN_free(r);
        BN_free(s);
        ECDSA_SIG_free(ecdsa);
        return false;
    }
    if (ECDSA_SIG_set0(ecdsa, r, s) != 1) {
        BN_free(r);
        BN_free(s);
        ECDSA_SIG_free(ecdsa);
        return false;
    }

    const int length = i2d_ECDSA_SIG(ecdsa, nullptr);
    if (length <= 0) {
        ECDSA_SIG_free(ecdsa);
        return false;
    }
    der.resize(static_cast<std::size_t>(length));
    unsigned char* cursor = der.data();
    const bool ok = i2d_ECDSA_SIG(ecdsa, &cursor) == length;
    ECDSA_SIG_free(ecdsa);
    return ok;
}

bool verify_brk(
    std::span<const std::uint8_t> public_key,
    std::span<const std::uint8_t> transcript,
    std::span<const std::uint8_t> signature
) {
    EVP_PKEY* key = import_native_public(public_key);
    if (key == nullptr) return false;

    std::vector<std::uint8_t> der_signature;
    if (!raw_signature_to_der(signature, der_signature)) {
        EVP_PKEY_free(key);
        return false;
    }

    EVP_MD_CTX* context = EVP_MD_CTX_new();
    const bool ok = context != nullptr &&
        EVP_DigestVerifyInit(context, nullptr, EVP_sha256(), nullptr, key) == 1 &&
        EVP_DigestVerify(
            context,
            der_signature.data(), der_signature.size(),
            transcript.data(), transcript.size()
        ) == 1;
    EVP_MD_CTX_free(context);
    EVP_PKEY_free(key);
    if (!der_signature.empty()) secure_zero(der_signature.data(), der_signature.size());
    return ok;
}

#endif

}  // namespace

struct DeviceSession::Impl {
    AttemptId attempt_id{};
    DeviceChallenge challenge{};
    P256PublicKey device_public_key{};
    std::uint64_t expires_at_ms{0};
    bool active{false};
#ifdef ESP_PLATFORM
    psa_key_id_t key_id{0};
#else
    EVP_PKEY* key{nullptr};
#endif

    void reset() {
#ifdef ESP_PLATFORM
        if (key_id != 0) {
            (void)psa_destroy_key(key_id);
            key_id = 0;
        }
#else
        EVP_PKEY_free(key);
        key = nullptr;
#endif
        clear_array(attempt_id);
        clear_array(challenge);
        clear_array(device_public_key);
        expires_at_ms = 0;
        active = false;
    }
};

DeviceSession::DeviceSession() : impl_(std::make_unique<Impl>()) {}

DeviceSession::~DeviceSession() {
    impl_->reset();
}

bool DeviceSession::begin(std::uint64_t now_ms, AttemptDescriptor& descriptor) {
    impl_->reset();
    if (!fill_random(impl_->attempt_id) || !fill_random(impl_->challenge)) {
        impl_->reset();
        return false;
    }

#ifdef ESP_PLATFORM
    if (psa_crypto_init() != PSA_SUCCESS) return false;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(
        &attributes,
        PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1)
    );
    psa_set_key_bits(&attributes, 256);
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_DERIVE);
    psa_set_key_algorithm(&attributes, PSA_ALG_ECDH);
    const psa_status_t generation_status = psa_generate_key(&attributes, &impl_->key_id);
    psa_reset_key_attributes(&attributes);
    if (generation_status != PSA_SUCCESS) {
        impl_->reset();
        return false;
    }
    std::size_t public_length = 0;
    if (psa_export_public_key(
            impl_->key_id,
            impl_->device_public_key.data(), impl_->device_public_key.size(),
            &public_length
        ) != PSA_SUCCESS ||
        public_length != impl_->device_public_key.size() ||
        impl_->device_public_key[0] != 0x04) {
        impl_->reset();
        return false;
    }
#else
    if (!generate_native_key(impl_->key, impl_->device_public_key)) {
        impl_->reset();
        return false;
    }
#endif

    impl_->expires_at_ms = deadline_from(now_ms);
    impl_->active = true;
    descriptor = AttemptDescriptor{
        .attempt_id = impl_->attempt_id,
        .challenge = impl_->challenge,
        .device_public_key = impl_->device_public_key,
        .expires_at_ms = impl_->expires_at_ms,
    };
    return true;
}

bool DeviceSession::active(std::uint64_t now_ms) const {
    return impl_->active && now_ms < impl_->expires_at_ms;
}

bool DeviceSession::expire(std::uint64_t now_ms) {
    if (!impl_->active || now_ms < impl_->expires_at_ms) return false;
    impl_->reset();
    return true;
}

void DeviceSession::cancel() {
    impl_->reset();
}

bool DeviceSession::matches_attempt(
    std::span<const std::uint8_t> attempt_id,
    std::uint64_t now_ms
) {
    if (!active(now_ms)) {
        impl_->reset();
        return false;
    }
    if (!constant_time_equal(attempt_id, impl_->attempt_id)) {
        impl_->reset();
        return false;
    }
    return true;
}

bool DeviceSession::verify_brk_signature(
    std::span<const std::uint8_t> brk_public_key,
    std::span<const std::uint8_t> transcript,
    std::span<const std::uint8_t> signature,
    std::uint64_t now_ms
) {
    if (!active(now_ms) ||
        brk_public_key.size() != kP256PublicKeyBytes ||
        brk_public_key[0] != 0x04 ||
        !bounded_nonempty(transcript, kMaxTranscriptBytes) ||
        signature.size() != kBrkSignatureBytes ||
        !verify_brk(brk_public_key, transcript, signature)) {
        impl_->reset();
        return false;
    }
    return true;
}

bool DeviceSession::open_vmk(
    std::span<const std::uint8_t> web_public_key,
    std::span<const std::uint8_t> hkdf_salt,
    std::span<const std::uint8_t> hkdf_info,
    std::span<const std::uint8_t> nonce,
    std::span<const std::uint8_t> ciphertext,
    std::span<const std::uint8_t> tag,
    std::span<const std::uint8_t> transcript_aad,
    std::uint64_t now_ms,
    Vmk& vmk
) {
    clear_array(vmk);
    if (!active(now_ms) ||
        web_public_key.size() != kP256PublicKeyBytes ||
        web_public_key[0] != 0x04 ||
        !bounded_nonempty(hkdf_salt, kMaxHkdfContextBytes) ||
        !bounded_nonempty(hkdf_info, kMaxHkdfContextBytes) ||
        nonce.size() != kSessionNonceBytes ||
        ciphertext.size() != kSessionKeyBytes ||
        tag.size() != kSessionTagBytes ||
        !bounded_nonempty(transcript_aad, kMaxTranscriptBytes)) {
        impl_->reset();
        return false;
    }

    std::array<std::uint8_t, kSessionKeyBytes> shared_secret{};
    std::array<std::uint8_t, kSessionKeyBytes> session_key{};
#ifdef ESP_PLATFORM
    std::size_t shared_length = 0;
    const bool shared_ok = psa_raw_key_agreement(
        PSA_ALG_ECDH,
        impl_->key_id,
        web_public_key.data(), web_public_key.size(),
        shared_secret.data(), shared_secret.size(),
        &shared_length
    ) == PSA_SUCCESS && shared_length == shared_secret.size();
#else
    const bool shared_ok = derive_native_shared(
        impl_->key,
        web_public_key,
        shared_secret
    );
#endif
    const bool derived = shared_ok && derive_hkdf(
        shared_secret,
        hkdf_salt,
        hkdf_info,
        session_key
    );
    clear_array(shared_secret);

    const bool opened = derived && decrypt_vmk_gcm(
        session_key,
        nonce,
        ciphertext,
        tag,
        transcript_aad,
        vmk
    );
    clear_array(session_key);

    // VMK delivery is one-shot. Success and failure both destroy the ephemeral
    // private key and attempt material so the transcript cannot be replayed.
    impl_->reset();
    if (!opened) clear_array(vmk);
    return opened;
}

}  // namespace m5auth::session
