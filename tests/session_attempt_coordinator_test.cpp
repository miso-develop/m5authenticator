#include <algorithm>
#include <array>
#include <cassert>
#include <cstdint>
#include <vector>

#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/params.h>

#include "m5auth/session/protocol_v2.hpp"

namespace {

using namespace m5auth::session;
using namespace m5auth::session::protocol_v2;

class FakePresence final : public PresenceBinding {
public:
    bool begin_presence(PresenceOperation operation, const AttemptId& attempt_id, std::uint64_t now_ms) override {
        const bool started = gate_.begin(operation, attempt_id, now_ms, generation_);
        if (started) {
            // This pure coordinator fixture has no physical button sampler, so
            // model the post-request neutral baseline explicitly. Hardware race
            // handling is covered by user_presence_test.cpp.
            gate_.observe_input_state(false);
            gate_.observe_input_state(false);
        }
        return started;
    }

    bool consume_presence(const AttemptId& attempt_id, std::uint64_t now_ms) override {
        return gate_.consume_confirmation(attempt_id, now_ms);
    }

    void cancel_presence() override { gate_.cancel(); }
    bool presence_confirmed() const override { return gate_.state() == PresenceState::kConfirmed; }

    bool press(std::uint64_t now_ms) {
        ++generation_;
        gate_.observe_input_state(true);
        return gate_.confirm_current(now_ms, generation_);
    }

    bool active() const { return gate_.active(); }

private:
    UserPresenceGate gate_;
    std::uint64_t generation_{0};
};

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

std::array<std::uint8_t, 32> derive_shared(EVP_PKEY* private_key, const P256PublicKey& peer_public_key) {
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
    const std::array<std::uint8_t, kHkdfSaltBytes>& salt,
    const std::vector<std::uint8_t>& info
) {
    EVP_PKEY_CTX* context = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
    assert(context != nullptr);
    assert(EVP_PKEY_derive_init(context) == 1);
    assert(EVP_PKEY_CTX_hkdf_mode(context, EVP_PKEY_HKDEF_MODE_EXTRACT_AND_EXPAND) == 1);
    assert(EVP_PKEY_CTX_set_hkdf_md(context, EVP_sha256()) == 1);
    assert(EVP_PKEY_CTX_set1_hkdf_salt(context, salt.data(), static_cast<int>(salt.size())) == 1);
    assert(EVP_PKEY_CTX_set1_hkdf_key(context, shared.data(), static_cast<int>(shared.size())) == 1);
    assert(EVP_PKEY_CTX_add1_hkdf_info(context, info.data(), static_cast<int>(info.size())) == 1);
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
        sealed.nonce[index] = static_cast<std::uint8_t>(0x60 + index);
    }
    EVP_CIPHER_CTX* context = EVP_CIPHER_CTX_new();
    assert(context != nullptr);
    int written = 0;
    int total = 0;
    assert(EVP_EncryptInit_ex(context, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1);
    assert(EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(sealed.nonce.size()), nullptr) == 1);
    assert(EVP_EncryptInit_ex(context, nullptr, nullptr, session_key.data(), sealed.nonce.data()) == 1);
    assert(EVP_EncryptUpdate(context, nullptr, &written, aad.data(), static_cast<int>(aad.size())) == 1);
    assert(EVP_EncryptUpdate(
        context,
        sealed.ciphertext.data(), &written,
        vmk.data(), static_cast<int>(vmk.size())
    ) == 1);
    total = written;
    assert(EVP_EncryptFinal_ex(context, sealed.ciphertext.data() + total, &written) == 1);
    total += written;
    assert(total == static_cast<int>(sealed.ciphertext.size()));
    assert(EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_GET_TAG, static_cast<int>(sealed.tag.size()), sealed.tag.data()) == 1);
    EVP_CIPHER_CTX_free(context);
    return sealed;
}

std::array<std::uint8_t, 64> sign_raw(EVP_PKEY* private_key, const std::vector<std::uint8_t>& transcript) {
    EVP_MD_CTX* context = EVP_MD_CTX_new();
    assert(context != nullptr);
    assert(EVP_DigestSignInit(context, nullptr, EVP_sha256(), nullptr, private_key) == 1);
    std::size_t der_length = 0;
    assert(EVP_DigestSign(context, nullptr, &der_length, transcript.data(), transcript.size()) == 1);
    std::vector<std::uint8_t> der(der_length);
    assert(EVP_DigestSign(context, der.data(), &der_length, transcript.data(), transcript.size()) == 1);
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

template <std::size_t N>
std::array<std::uint8_t, N> sequence(std::uint8_t start) {
    std::array<std::uint8_t, N> value{};
    for (std::size_t index = 0; index < N; ++index) value[index] = static_cast<std::uint8_t>(start + index);
    return value;
}

std::vector<std::uint8_t> transcript_for(
    const BeginContext& context,
    const AttemptDescriptor& descriptor,
    const P256PublicKey& web_public
) {
    TranscriptInput input{};
    input.operation = context.operation;
    input.device_id = context.device_id;
    input.vault_id = context.vault_id;
    input.expected_generation = context.expected_generation;
    input.registration_id = context.registration_id;
    input.registration_epoch = context.registration_epoch;
    input.attempt_id = descriptor.attempt_id;
    input.challenge = descriptor.challenge;
    input.device_ephemeral_public_key = descriptor.device_public_key;
    input.web_ephemeral_public_key = web_public;
    input.current_brk_public_key = context.current_brk_public_key;
    input.proposed_brk_public_key = context.proposed_brk_public_key;
    std::vector<std::uint8_t> transcript;
    assert(encode_transcript(input, &transcript));
    return transcript;
}

std::array<std::uint8_t, kHkdfSaltBytes> salt_for(const AttemptDescriptor& descriptor) {
    std::array<std::uint8_t, kHkdfSaltBytes> salt{};
    std::copy(descriptor.attempt_id.begin(), descriptor.attempt_id.end(), salt.begin());
    std::copy(descriptor.challenge.begin(), descriptor.challenge.end(), salt.begin() + kAttemptIdBytes);
    return salt;
}

}  // namespace

int main() {
    FakePresence presence;
    AttemptCoordinator coordinator(presence);

    P256PublicKey brk_public{};
    EVP_PKEY* brk_private = generate_p256(brk_public);

    BeginContext context{};
    context.operation = Operation::kTrustedBrowserUnlock;
    context.device_id = "stick3-test";
    context.vault_id = sequence<kVaultIdBytes>(0x10);
    context.expected_generation = 7;
    context.registration_id = sequence<kRegistrationIdBytes>(0x30);
    context.registration_epoch = 3;
    context.current_brk_public_key = brk_public;

    AttemptDescriptor descriptor{};
    assert(coordinator.begin(context, 1'000, &descriptor));
    assert(coordinator.state() == AttemptState::kAwaitingAuthorization);

    P256PublicKey web_public{};
    EVP_PKEY* web_private = generate_p256(web_public);
    const std::vector<std::uint8_t> transcript = transcript_for(context, descriptor, web_public);
    auto signature = sign_raw(brk_private, transcript);
    assert(coordinator.authorize(web_public, signature, 1'001));
    assert(presence.active());
    assert(coordinator.state() == AttemptState::kAwaitingPresence);

    assert(presence.press(1'002));
    assert(coordinator.state() == AttemptState::kConfirmed);

    const auto salt = salt_for(descriptor);
    auto shared = derive_shared(web_private, descriptor.device_public_key);
    auto session_key = hkdf(shared, salt, transcript);
    Vmk expected_vmk = sequence<kSessionKeyBytes>(0xa0);
    const SealedVmk sealed = seal_vmk(session_key, expected_vmk, transcript);
    Vmk opened{};
    assert(coordinator.complete(sealed.nonce, sealed.ciphertext, sealed.tag, 1'003, &opened));
    assert(opened == expected_vmk);
    assert(!coordinator.active());
    assert(!presence.active());

    opened.fill(0xa5);
    assert(!coordinator.complete(sealed.nonce, sealed.ciphertext, sealed.tag, 1'004, &opened));
    assert(std::all_of(opened.begin(), opened.end(), [](std::uint8_t byte) { return byte == 0; }));

    AttemptDescriptor invalid{};
    assert(coordinator.begin(context, 2'000, &invalid));
    EVP_PKEY_free(web_private);
    web_private = generate_p256(web_public);
    const auto invalid_transcript = transcript_for(context, invalid, web_public);
    signature = sign_raw(brk_private, invalid_transcript);
    signature[0] ^= 0x01;
    assert(!coordinator.authorize(web_public, signature, 2'001));
    assert(!coordinator.active());
    assert(!presence.active());

    AttemptDescriptor first{};
    AttemptDescriptor second{};
    assert(coordinator.begin(context, 3'000, &first));
    assert(coordinator.begin(context, 3'010, &second));
    assert(first.attempt_id != second.attempt_id);
    assert(coordinator.active());
    coordinator.disconnect();
    assert(!coordinator.active());
    assert(!presence.active());

    assert(coordinator.begin(context, 4'000, &first));
    assert(!coordinator.expire(33'999));
    assert(coordinator.expire(34'000));
    assert(!coordinator.active());

    expected_vmk.fill(0);
    opened.fill(0);
    shared.fill(0);
    session_key.fill(0);
    EVP_PKEY_free(web_private);
    EVP_PKEY_free(brk_private);
    return 0;
}
