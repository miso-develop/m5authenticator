#include <algorithm>
#include <array>
#include <cassert>
#include <cstdint>
#include <string_view>
#include <vector>

#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/params.h>

#include "m5auth/session/session.hpp"

namespace {

using m5auth::session::P256PublicKey;
using m5auth::session::Vmk;

EVP_PKEY* generate_p256(P256PublicKey& public_key) {
    EVP_PKEY_CTX* context = EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr);
    assert(context != nullptr);
    assert(EVP_PKEY_keygen_init(context) == 1);
    assert(EVP_PKEY_CTX_set_group_name(context, "P-256") == 1);

    EVP_PKEY* key = nullptr;
    assert(EVP_PKEY_generate(context, &key) == 1);
    EVP_PKEY_CTX_free(context);
    assert(key != nullptr);

    std::size_t length = 0;
    assert(EVP_PKEY_get_octet_string_param(
        key,
        OSSL_PKEY_PARAM_PUB_KEY,
        public_key.data(), public_key.size(),
        &length
    ) == 1);
    assert(length == public_key.size());
    assert(public_key[0] == 0x04);
    return key;
}

EVP_PKEY* import_public(const P256PublicKey& public_key) {
    EVP_PKEY_CTX* context = EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr);
    assert(context != nullptr);
    assert(EVP_PKEY_fromdata_init(context) == 1);
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
    assert(EVP_PKEY_fromdata(context, &key, EVP_PKEY_PUBLIC_KEY, parameters) == 1);
    EVP_PKEY_CTX_free(context);
    return key;
}

std::array<std::uint8_t, 32> derive_shared(
    EVP_PKEY* private_key,
    const P256PublicKey& peer_public_key
) {
    EVP_PKEY* peer = import_public(peer_public_key);
    EVP_PKEY_CTX* context = EVP_PKEY_CTX_new_from_pkey(nullptr, private_key, nullptr);
    assert(context != nullptr);
    assert(EVP_PKEY_derive_init(context) == 1);
    assert(EVP_PKEY_derive_set_peer(context, peer) == 1);
    std::array<std::uint8_t, 32> shared{};
    std::size_t length = shared.size();
    assert(EVP_PKEY_derive(context, shared.data(), &length) == 1);
    assert(length == shared.size());
    EVP_PKEY_CTX_free(context);
    EVP_PKEY_free(peer);
    return shared;
}

std::array<std::uint8_t, 32> hkdf(
    const std::array<std::uint8_t, 32>& shared,
    const std::vector<std::uint8_t>& salt,
    const std::vector<std::uint8_t>& info
) {
    EVP_PKEY_CTX* context = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
    assert(context != nullptr);
    assert(EVP_PKEY_derive_init(context) == 1);
    assert(EVP_PKEY_CTX_hkdf_mode(context, EVP_PKEY_HKDEF_MODE_EXTRACT_AND_EXPAND) == 1);
    assert(EVP_PKEY_CTX_set_hkdf_md(context, EVP_sha256()) == 1);
    assert(EVP_PKEY_CTX_set1_hkdf_salt(
        context,
        salt.data(), static_cast<int>(salt.size())
    ) == 1);
    assert(EVP_PKEY_CTX_set1_hkdf_key(
        context,
        shared.data(), static_cast<int>(shared.size())
    ) == 1);
    assert(EVP_PKEY_CTX_add1_hkdf_info(
        context,
        info.data(), static_cast<int>(info.size())
    ) == 1);
    std::array<std::uint8_t, 32> output{};
    std::size_t length = output.size();
    assert(EVP_PKEY_derive(context, output.data(), &length) == 1);
    assert(length == output.size());
    EVP_PKEY_CTX_free(context);
    return output;
}

struct SealedVmk {
    std::array<std::uint8_t, 12> nonce{};
    Vmk ciphertext{};
    std::array<std::uint8_t, 16> tag{};
};

SealedVmk seal_vmk(
    const std::array<std::uint8_t, 32>& session_key,
    const Vmk& vmk,
    const std::vector<std::uint8_t>& aad
) {
    SealedVmk sealed;
    for (std::size_t index = 0; index < sealed.nonce.size(); ++index) {
        sealed.nonce[index] = static_cast<std::uint8_t>(0x30 + index);
    }

    EVP_CIPHER_CTX* context = EVP_CIPHER_CTX_new();
    assert(context != nullptr);
    int written = 0;
    int total = 0;
    assert(EVP_EncryptInit_ex(context, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1);
    assert(EVP_CIPHER_CTX_ctrl(
        context,
        EVP_CTRL_GCM_SET_IVLEN,
        static_cast<int>(sealed.nonce.size()),
        nullptr
    ) == 1);
    assert(EVP_EncryptInit_ex(
        context,
        nullptr,
        nullptr,
        session_key.data(),
        sealed.nonce.data()
    ) == 1);
    assert(EVP_EncryptUpdate(
        context,
        nullptr,
        &written,
        aad.data(), static_cast<int>(aad.size())
    ) == 1);
    assert(EVP_EncryptUpdate(
        context,
        sealed.ciphertext.data(),
        &written,
        vmk.data(), static_cast<int>(vmk.size())
    ) == 1);
    total = written;
    assert(EVP_EncryptFinal_ex(
        context,
        sealed.ciphertext.data() + total,
        &written
    ) == 1);
    total += written;
    assert(total == static_cast<int>(sealed.ciphertext.size()));
    assert(EVP_CIPHER_CTX_ctrl(
        context,
        EVP_CTRL_GCM_GET_TAG,
        static_cast<int>(sealed.tag.size()),
        sealed.tag.data()
    ) == 1);
    EVP_CIPHER_CTX_free(context);
    return sealed;
}

std::vector<std::uint8_t> text(std::string_view value) {
    return std::vector<std::uint8_t>(value.begin(), value.end());
}

std::array<std::uint8_t, 64> sign_raw(
    EVP_PKEY* private_key,
    const std::vector<std::uint8_t>& transcript
) {
    EVP_MD_CTX* context = EVP_MD_CTX_new();
    assert(context != nullptr);
    assert(EVP_DigestSignInit(context, nullptr, EVP_sha256(), nullptr, private_key) == 1);
    std::size_t der_length = 0;
    assert(EVP_DigestSign(
        context,
        nullptr, &der_length,
        transcript.data(), transcript.size()
    ) == 1);
    std::vector<std::uint8_t> der(der_length);
    assert(EVP_DigestSign(
        context,
        der.data(), &der_length,
        transcript.data(), transcript.size()
    ) == 1);
    der.resize(der_length);
    EVP_MD_CTX_free(context);

    const unsigned char* cursor = der.data();
    ECDSA_SIG* signature = d2i_ECDSA_SIG(nullptr, &cursor, static_cast<long>(der.size()));
    assert(signature != nullptr);
    const BIGNUM* r = nullptr;
    const BIGNUM* s = nullptr;
    ECDSA_SIG_get0(signature, &r, &s);
    std::array<std::uint8_t, 64> raw{};
    assert(BN_bn2binpad(r, raw.data(), 32) == 32);
    assert(BN_bn2binpad(s, raw.data() + 32, 32) == 32);
    ECDSA_SIG_free(signature);
    return raw;
}

void seal_for_descriptor(
    const m5auth::session::AttemptDescriptor& descriptor,
    EVP_PKEY*& web_key,
    P256PublicKey& web_public,
    const std::vector<std::uint8_t>& salt,
    const std::vector<std::uint8_t>& info,
    const Vmk& vmk,
    const std::vector<std::uint8_t>& aad,
    SealedVmk& sealed
) {
    web_key = generate_p256(web_public);
    auto shared = derive_shared(web_key, descriptor.device_public_key);
    auto session_key = hkdf(shared, salt, info);
    sealed = seal_vmk(session_key, vmk, aad);
    shared.fill(0);
    session_key.fill(0);
}

}  // namespace

int main() {
    using namespace m5auth::session;

    DeviceSession device;
    AttemptDescriptor first{};
    assert(device.begin(1'000, first));
    assert(device.active(1'000));
    assert(first.expires_at_ms == 31'000);
    assert(first.device_public_key[0] == 0x04);

    AttemptDescriptor second{};
    assert(device.begin(1'100, second));
    assert(first.attempt_id != second.attempt_id);
    assert(first.challenge != second.challenge);
    assert(first.device_public_key != second.device_public_key);

    // Replaying the superseded attempt fails closed and destroys the current one.
    assert(!device.matches_attempt(first.attempt_id, 1'101));
    assert(!device.active(1'101));

    const std::vector<std::uint8_t> salt = text("synthetic-session-salt");
    const std::vector<std::uint8_t> info = text("m5auth-session-v2-test");
    const std::vector<std::uint8_t> aad = text("synthetic-canonical-transcript");
    Vmk expected_vmk{};
    for (std::size_t index = 0; index < expected_vmk.size(); ++index) {
        expected_vmk[index] = static_cast<std::uint8_t>(0x80 + index);
    }

    AttemptDescriptor opening{};
    assert(device.begin(2'000, opening));
    EVP_PKEY* web_key = nullptr;
    P256PublicKey web_public{};
    SealedVmk sealed{};
    seal_for_descriptor(
        opening,
        web_key,
        web_public,
        salt,
        info,
        expected_vmk,
        aad,
        sealed
    );
    Vmk opened{};
    assert(device.open_vmk(
        web_public,
        salt,
        info,
        sealed.nonce,
        sealed.ciphertext,
        sealed.tag,
        aad,
        2'001,
        opened
    ));
    assert(opened == expected_vmk);
    assert(!device.active(2'001));
    opened.fill(0);
    EVP_PKEY_free(web_key);

    // Authentication failure wipes the output and the one-shot attempt.
    AttemptDescriptor tampered_descriptor{};
    assert(device.begin(3'000, tampered_descriptor));
    web_key = nullptr;
    seal_for_descriptor(
        tampered_descriptor,
        web_key,
        web_public,
        salt,
        info,
        expected_vmk,
        aad,
        sealed
    );
    sealed.tag[0] ^= 0x01;
    opened.fill(0xa5);
    assert(!device.open_vmk(
        web_public,
        salt,
        info,
        sealed.nonce,
        sealed.ciphertext,
        sealed.tag,
        aad,
        3'001,
        opened
    ));
    assert(std::all_of(opened.begin(), opened.end(), [](std::uint8_t value) {
        return value == 0;
    }));
    assert(!device.active(3'001));
    EVP_PKEY_free(web_key);

    // Trusted Browser BRK signatures use raw 64-byte P1363 framing.
    AttemptDescriptor signed_attempt{};
    assert(device.begin(4'000, signed_attempt));
    P256PublicKey brk_public{};
    EVP_PKEY* brk_private = generate_p256(brk_public);
    const std::vector<std::uint8_t> transcript = text("synthetic-signed-transcript");
    auto signature = sign_raw(brk_private, transcript);
    assert(device.verify_brk_signature(
        brk_public,
        transcript,
        signature,
        4'001
    ));
    signature[63] ^= 0x01;
    assert(!device.verify_brk_signature(
        brk_public,
        transcript,
        signature,
        4'002
    ));
    assert(!device.active(4'002));
    EVP_PKEY_free(brk_private);

    AttemptDescriptor malformed{};
    assert(device.begin(5'000, malformed));
    std::array<std::uint8_t, 64> short_key{};
    opened.fill(0xa5);
    assert(!device.open_vmk(
        short_key,
        salt,
        info,
        sealed.nonce,
        sealed.ciphertext,
        sealed.tag,
        aad,
        5'001,
        opened
    ));
    assert(!device.active(5'001));

    AttemptDescriptor expiring{};
    assert(device.begin(6'000, expiring));
    assert(!device.expire(35'999));
    assert(device.expire(36'000));
    assert(!device.active(36'000));

    expected_vmk.fill(0);
    return 0;
}
