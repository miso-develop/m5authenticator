#include "m5auth/vault.hpp"

#include <array>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <string>
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

    return 0;
}
