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

    // Shipped v0.1.0 PT1/AAD1 remains byte-for-byte unchanged.
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
    std::uint16_t decoded_format = 0;
    assert(decode_plaintext(encoded, decoded, &decoded_format));
    assert(decoded_format == kVaultFormatVersion1);
    assert(!decoded.auto_lock_days.has_value());
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

    // PT1 exact-end remains mandatory; it is not retrofitted with extensions.
    std::vector<std::uint8_t> pt1_trailing = encoded;
    pt1_trailing.push_back(0x00);
    VaultPlaintext rejected_plaintext;
    assert(!decode_plaintext(pt1_trailing, rejected_plaintext));

    // Format 2 has a distinct framing/AAD domain and carries only the bounded
    // optional automatic-lock policy after the unchanged credential/Wi-Fi body.
    std::vector<std::uint8_t> aad2;
    assert(build_vault_aad(
        vault_id,
        7,
        aad2,
        kVaultFormatVersion2,
        kTargetStorageSchemaVersion
    ));
    assert(
        hex(aad2.data(), aad2.size()) ==
        "4d35415554482d564c542d4141443200"
        "0002"
        "0002"
        "000102030405060708090a0b0c0d0e0f"
        "0000000000000007"
    );
    assert(aad2 != aad);

    VaultPlaintext format2_unset = sample_vault();
    std::vector<std::uint8_t> encoded2_unset;
    assert(encode_plaintext(format2_unset, encoded2_unset, kVaultFormatVersion2));
    VaultPlaintext decoded2_unset;
    decoded_format = 0;
    assert(decode_plaintext(encoded2_unset, decoded2_unset, &decoded_format));
    assert(decoded_format == kVaultFormatVersion2);
    assert(!decoded2_unset.auto_lock_days.has_value());

    VaultPlaintext format2_one = sample_vault();
    format2_one.auto_lock_days = 1;
    std::vector<std::uint8_t> encoded2_one;
    assert(encode_plaintext(format2_one, encoded2_one, kVaultFormatVersion2));
    VaultPlaintext decoded2_one;
    decoded_format = 0;
    assert(decode_plaintext(encoded2_one, decoded2_one, &decoded_format));
    assert(decoded_format == kVaultFormatVersion2);
    assert(decoded2_one.auto_lock_days == std::optional<std::uint8_t>{1});

    VaultPlaintext format2_thirty_one = sample_vault();
    format2_thirty_one.auto_lock_days = 31;
    std::vector<std::uint8_t> encoded2_thirty_one;
    assert(encode_plaintext(
        format2_thirty_one,
        encoded2_thirty_one,
        kVaultFormatVersion2
    ));
    VaultPlaintext decoded2_thirty_one;
    assert(decode_plaintext(encoded2_thirty_one, decoded2_thirty_one));
    assert(decoded2_thirty_one.auto_lock_days == std::optional<std::uint8_t>{31});

    VaultPlaintext invalid_auto_lock = sample_vault();
    invalid_auto_lock.auto_lock_days = 0;
    std::vector<std::uint8_t> invalid_auto_lock_encoded;
    assert(!encode_plaintext(
        invalid_auto_lock,
        invalid_auto_lock_encoded,
        kVaultFormatVersion2
    ));
    invalid_auto_lock.auto_lock_days = 32;
    assert(!encode_plaintext(
        invalid_auto_lock,
        invalid_auto_lock_encoded,
        kVaultFormatVersion2
    ));
    // F1 cannot silently discard a Format-2-only logical setting.
    invalid_auto_lock.auto_lock_days = 1;
    assert(!encode_plaintext(
        invalid_auto_lock,
        invalid_auto_lock_encoded,
        kVaultFormatVersion1
    ));

    std::vector<std::uint8_t> invalid_presence = encoded2_unset;
    assert(!invalid_presence.empty());
    invalid_presence.back() = 2;
    assert(!decode_plaintext(invalid_presence, rejected_plaintext));

    std::vector<std::uint8_t> truncated_setting = encoded2_one;
    assert(!truncated_setting.empty());
    truncated_setting.pop_back();
    assert(!decode_plaintext(truncated_setting, rejected_plaintext));

    std::vector<std::uint8_t> pt2_trailing = encoded2_unset;
    pt2_trailing.push_back(0xaa);
    assert(!decode_plaintext(pt2_trailing, rejected_plaintext));

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
    assert(known_answer.vault_format_version == kVaultFormatVersion1);
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

    VaultEnvelope format2_answer;
    assert(encrypt_vault_with_nonce(
        encoded2_one,
        vmk,
        vault_id,
        7,
        nonce,
        format2_answer,
        kVaultFormatVersion2
    ));
    assert(format2_answer.vault_format_version == kVaultFormatVersion2);
    opened.clear();
    assert(decrypt_vault(format2_answer, vmk, opened));
    assert(opened == encoded2_one);
    // Merely substituting the envelope version cannot cross-authenticate AAD1/AAD2.
    VaultEnvelope cross_domain = format2_answer;
    cross_domain.vault_format_version = kVaultFormatVersion1;
    assert(!decrypt_vault(cross_domain, vmk, opened));

    assert(!build_vault_aad(
        vault_id,
        1,
        aad,
        kVaultFormatVersion2 + 1,
        kTargetStorageSchemaVersion
    ));
    assert(!build_vault_aad(
        vault_id,
        1,
        aad,
        kVaultFormatVersion1,
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