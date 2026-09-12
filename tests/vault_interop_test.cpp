#include "m5auth/vault.hpp"

#include <algorithm>
#include <array>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

using namespace m5auth::vault;

namespace {

std::string hex(const std::uint8_t* bytes, std::size_t length) {
    static constexpr char kDigits[] = "0123456789abcdef";
    std::string result;
    result.reserve(length * 2);
    for (std::size_t index = 0; index < length; ++index) {
        result += kDigits[bytes[index] >> 4];
        result += kDigits[bytes[index] & 0x0f];
    }
    return result;
}

template <std::size_t N>
std::array<std::uint8_t, N> sequence(std::uint8_t start) {
    std::array<std::uint8_t, N> result{};
    for (std::size_t index = 0; index < N; ++index) {
        result[index] = static_cast<std::uint8_t>(start + index);
    }
    return result;
}

template <typename Needle>
bool contains_bytes(const std::vector<std::uint8_t>& haystack, const Needle& needle) {
    return std::search(haystack.begin(), haystack.end(), needle.begin(), needle.end()) != haystack.end();
}

bool contains_text(const std::vector<std::uint8_t>& haystack, std::string_view needle) {
    return std::search(haystack.begin(), haystack.end(), needle.begin(), needle.end()) != haystack.end();
}

VaultPlaintext sample_vault() {
    VaultPlaintext vault;
    CredentialRecord credential;
    credential.credential_id = sequence<kCredentialIdBytes>(0x20);
    for (int index = 0; index < 20; ++index) {
        credential.secret.push_back(static_cast<std::uint8_t>(0x40 + index));
    }
    credential.issuer = "synthetic-issuer-only";
    credential.account = "synthetic-account-only";
    credential.display_name = "synthetic-display-only";
    credential.algorithm = TotpAlgorithm::kSha1;
    credential.digits = 6;
    credential.period_seconds = 30;
    credential.manual_order = 0;
    vault.credentials.push_back(credential);
    vault.wifi = WifiRecord{"synthetic-ssid-only", "synthetic-network-pass-only"};
    return vault;
}

}  // namespace

int main() {
    const auto vault_id = sequence<kVaultIdBytes>(0x00);

    std::vector<std::uint8_t> aad;
    assert(build_vault_aad(vault_id, 7, aad));
    assert(
        hex(aad.data(), aad.size()) ==
        "4d35415554482d564c542d4141443100"
        "0001"
        "0002"
        "000102030405060708090a0b0c0d0e0f"
        "0000000000000007"
    );

    const VaultPlaintext original = sample_vault();
    std::vector<std::uint8_t> encoded;
    assert(encode_plaintext(original, encoded));

    VaultPlaintext decoded;
    assert(decode_plaintext(encoded, decoded));
    assert(decoded.credentials.size() == 1);
    assert(decoded.credentials[0].secret == original.credentials[0].secret);
    assert(decoded.credentials[0].issuer == original.credentials[0].issuer);
    assert(decoded.credentials[0].account == original.credentials[0].account);
    assert(decoded.credentials[0].display_name == original.credentials[0].display_name);
    assert(decoded.credentials[0].algorithm == TotpAlgorithm::kSha1);
    assert(decoded.credentials[0].digits == 6);
    assert(decoded.credentials[0].period_seconds == 30);
    assert(decoded.wifi.has_value());
    assert(decoded.wifi->ssid == original.wifi->ssid);
    assert(decoded.wifi->password == original.wifi->password);

    const auto vmk = sequence<kVmkBytes>(0x00);

    // Device persistence stores the authenticated Vault envelope, not this
    // plaintext. Inspect the exact encrypted payload that is handed to the NVS
    // persistence layer and fail if any synthetic private marker or VMK is
    // present verbatim. The NVS contract test independently pins that only the
    // envelope ciphertext plus bounded non-secret framing/registration state is
    // persisted outside the Vault.
    VaultEnvelope persisted_private_state;
    assert(encrypt_vault_with_nonce(
        encoded,
        vmk,
        vault_id,
        8,
        sequence<kVaultNonceBytes>(0xc0),
        persisted_private_state
    ));
    for (const std::string_view marker : {
        "synthetic-issuer-only",
        "synthetic-account-only",
        "synthetic-display-only",
        "synthetic-ssid-only",
        "synthetic-network-pass-only",
    }) {
        assert(!contains_text(persisted_private_state.ciphertext, marker));
    }
    assert(!contains_bytes(
        persisted_private_state.ciphertext,
        original.credentials[0].secret
    ));
    assert(!contains_bytes(persisted_private_state.ciphertext, vmk));

    const auto nonce = sequence<kVaultNonceBytes>(0xa0);
    const std::string payload_text = "synthetic-vault-payload-only";
    const std::vector<std::uint8_t> payload(payload_text.begin(), payload_text.end());

    VaultEnvelope known_answer;
    assert(encrypt_vault_with_nonce(payload, vmk, vault_id, 7, nonce, known_answer));
    assert(
        hex(known_answer.ciphertext.data(), known_answer.ciphertext.size()) ==
        "956112592dae76d60148f1b27216b4f300cd207cfdd62641f3604aff"
    );
    assert(
        hex(known_answer.tag.data(), known_answer.tag.size()) ==
        "fe8172af15306428c847087428f8395c"
    );

    std::vector<std::uint8_t> opened;
    assert(decrypt_vault(known_answer, vmk, opened));
    assert(opened == payload);

    VaultEnvelope corrupted = known_answer;
    corrupted.tag[0] ^= 0x01;
    opened = {0xaa};
    assert(!decrypt_vault(corrupted, vmk, opened));
    assert(opened == std::vector<std::uint8_t>({0xaa}));

    VaultEnvelope wrong_generation = known_answer;
    ++wrong_generation.generation;
    assert(!decrypt_vault(wrong_generation, vmk, opened));

    assert(!build_vault_aad(
        vault_id,
        1,
        aad,
        kVaultFormatVersion + 1,
        kTargetStorageSchemaVersion
    ));
    assert(!build_vault_aad(
        vault_id,
        1,
        aad,
        kVaultFormatVersion,
        kTargetStorageSchemaVersion + 1
    ));

    VaultEnvelope random_first;
    VaultEnvelope random_second;
    assert(encrypt_vault(payload, vmk, vault_id, 9, random_first));
    assert(encrypt_vault(payload, vmk, vault_id, 9, random_second));
    assert(random_first.nonce != random_second.nonce);
    assert(random_first.ciphertext != random_second.ciphertext);

    VaultPlaintext invalid_utf8 = sample_vault();
    invalid_utf8.credentials[0].issuer.assign(1, static_cast<char>(0xff));
    std::vector<std::uint8_t> invalid_encoded;
    assert(!encode_plaintext(invalid_utf8, invalid_encoded));

    std::vector<std::uint8_t> wrap_aad;
    assert(build_vmk_wrap_aad(vault_id, wrap_aad));
    assert(
        hex(wrap_aad.data(), wrap_aad.size()) ==
        "4d35415554482d564d4b2d575241503100"
        "0001"
        "0001"
        "000102030405060708090a0b0c0d0e0f"
    );

    const std::array<std::uint8_t, kVmkBytes> wrapping_key = {
        0xfe, 0x49, 0x5a, 0x7c, 0x9e, 0x22, 0x44, 0xd9,
        0x21, 0x16, 0x9b, 0x17, 0x7a, 0xd0, 0x86, 0x86,
        0x1d, 0xb2, 0x97, 0xc9, 0x68, 0x4f, 0x6a, 0x83,
        0x8b, 0xeb, 0xc5, 0x37, 0x65, 0xa6, 0x5b, 0x97,
    };
    const auto wrap_nonce = sequence<kVaultNonceBytes>(0xb0);
    VmkWrapEnvelope wrapped;
    assert(wrap_vmk_with_key_and_nonce(vmk, wrapping_key, vault_id, wrap_nonce, wrapped));
    assert(
        hex(wrapped.ciphertext.data(), wrapped.ciphertext.size()) ==
        "539fe562291b3e6503ec2f35c42cc8fd8b7e6ece98eed59410e780eabbd75fd5"
    );
    assert(
        hex(wrapped.tag.data(), wrapped.tag.size()) ==
        "04f7af67328726ba0bc6bc1c48a74f69"
    );

    std::array<std::uint8_t, kVmkBytes> unwrapped{};
    assert(unwrap_vmk_with_key(wrapped, wrapping_key, unwrapped));
    assert(unwrapped == vmk);

    VmkWrapEnvelope invalid_wrap = wrapped;
    invalid_wrap.tag[0] ^= 0x01;
    unwrapped.fill(0xaa);
    assert(!unwrap_vmk_with_key(invalid_wrap, wrapping_key, unwrapped));
    for (const auto byte : unwrapped) assert(byte == 0xaa);

    assert(!build_vmk_wrap_aad(
        vault_id,
        wrap_aad,
        kRecoveryPackageVersion + 1,
        kVmkWrapVersion
    ));
    assert(!build_vmk_wrap_aad(
        vault_id,
        wrap_aad,
        kRecoveryPackageVersion,
        kVmkWrapVersion + 1
    ));

    return 0;
}
