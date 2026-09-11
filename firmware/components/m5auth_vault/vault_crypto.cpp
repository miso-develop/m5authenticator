#include "m5auth/vault.hpp"

#include <algorithm>
#include <climits>

#ifdef ESP_PLATFORM
#include "esp_random.h"
#include "mbedtls/gcm.h"
#else
#include <openssl/evp.h>
#include <openssl/rand.h>
#endif

namespace m5auth::vault {
namespace {

void secure_zero_memory(void* data, std::size_t size) {
    volatile auto* cursor = static_cast<volatile std::uint8_t*>(data);
    while (size-- > 0) {
        *cursor++ = 0;
    }
}

void clear_bytes(std::vector<std::uint8_t>& value) {
    if (!value.empty()) {
        secure_zero_memory(value.data(), value.size());
    }
}

bool fill_random_nonce(std::array<std::uint8_t, kVaultNonceBytes>& nonce) {
#ifdef ESP_PLATFORM
    esp_fill_random(nonce.data(), nonce.size());
    return true;
#else
    return RAND_bytes(nonce.data(), static_cast<int>(nonce.size())) == 1;
#endif
}

#ifdef ESP_PLATFORM
bool aes_gcm_encrypt(
    const std::vector<std::uint8_t>& plaintext,
    const std::array<std::uint8_t, kVmkBytes>& key,
    const std::array<std::uint8_t, kVaultNonceBytes>& nonce,
    const std::vector<std::uint8_t>& aad,
    std::vector<std::uint8_t>& ciphertext,
    std::array<std::uint8_t, kVaultTagBytes>& tag
) {
    ciphertext.assign(plaintext.size() + 1, 0);

    mbedtls_gcm_context context;
    mbedtls_gcm_init(&context);
    const bool ok =
        mbedtls_gcm_setkey(&context, MBEDTLS_CIPHER_ID_AES, key.data(), 256) == 0 &&
        mbedtls_gcm_crypt_and_tag(
            &context,
            MBEDTLS_GCM_ENCRYPT,
            plaintext.size(),
            nonce.data(),
            nonce.size(),
            aad.data(),
            aad.size(),
            plaintext.data(),
            ciphertext.data(),
            tag.size(),
            tag.data()
        ) == 0;
    mbedtls_gcm_free(&context);

    if (!ok) {
        clear_bytes(ciphertext);
        tag.fill(0);
        return false;
    }
    ciphertext.resize(plaintext.size());
    return true;
}

bool aes_gcm_decrypt(
    const std::vector<std::uint8_t>& ciphertext,
    const std::array<std::uint8_t, kVmkBytes>& key,
    const std::array<std::uint8_t, kVaultNonceBytes>& nonce,
    const std::vector<std::uint8_t>& aad,
    const std::array<std::uint8_t, kVaultTagBytes>& tag,
    std::vector<std::uint8_t>& plaintext
) {
    plaintext.assign(ciphertext.size() + 1, 0);

    mbedtls_gcm_context context;
    mbedtls_gcm_init(&context);
    const bool ok =
        mbedtls_gcm_setkey(&context, MBEDTLS_CIPHER_ID_AES, key.data(), 256) == 0 &&
        mbedtls_gcm_auth_decrypt(
            &context,
            ciphertext.size(),
            nonce.data(),
            nonce.size(),
            aad.data(),
            aad.size(),
            tag.data(),
            tag.size(),
            ciphertext.data(),
            plaintext.data()
        ) == 0;
    mbedtls_gcm_free(&context);

    if (!ok) {
        clear_bytes(plaintext);
        return false;
    }
    plaintext.resize(ciphertext.size());
    return true;
}
#else
bool sizes_fit_openssl(
    const std::vector<std::uint8_t>& payload,
    const std::vector<std::uint8_t>& aad
) {
    return payload.size() <= static_cast<std::size_t>(INT_MAX) &&
           aad.size() <= static_cast<std::size_t>(INT_MAX);
}

bool aes_gcm_encrypt(
    const std::vector<std::uint8_t>& plaintext,
    const std::array<std::uint8_t, kVmkBytes>& key,
    const std::array<std::uint8_t, kVaultNonceBytes>& nonce,
    const std::vector<std::uint8_t>& aad,
    std::vector<std::uint8_t>& ciphertext,
    std::array<std::uint8_t, kVaultTagBytes>& tag
) {
    if (!sizes_fit_openssl(plaintext, aad)) return false;

    ciphertext.assign(plaintext.size() + 16, 0);
    EVP_CIPHER_CTX* context = EVP_CIPHER_CTX_new();
    if (context == nullptr) return false;

    int written = 0;
    int total = 0;
    bool ok =
        EVP_EncryptInit_ex(context, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1 &&
        EVP_CIPHER_CTX_ctrl(
            context,
            EVP_CTRL_GCM_SET_IVLEN,
            static_cast<int>(nonce.size()),
            nullptr
        ) == 1 &&
        EVP_EncryptInit_ex(context, nullptr, nullptr, key.data(), nonce.data()) == 1 &&
        EVP_EncryptUpdate(
            context,
            nullptr,
            &written,
            aad.data(),
            static_cast<int>(aad.size())
        ) == 1 &&
        EVP_EncryptUpdate(
            context,
            ciphertext.data(),
            &written,
            plaintext.data(),
            static_cast<int>(plaintext.size())
        ) == 1;
    total = written;

    if (ok) {
        ok = EVP_EncryptFinal_ex(context, ciphertext.data() + total, &written) == 1;
        total += written;
    }
    if (ok) {
        ok = EVP_CIPHER_CTX_ctrl(
            context,
            EVP_CTRL_GCM_GET_TAG,
            static_cast<int>(tag.size()),
            tag.data()
        ) == 1;
    }
    EVP_CIPHER_CTX_free(context);

    if (!ok) {
        clear_bytes(ciphertext);
        tag.fill(0);
        return false;
    }
    ciphertext.resize(static_cast<std::size_t>(total));
    return true;
}

bool aes_gcm_decrypt(
    const std::vector<std::uint8_t>& ciphertext,
    const std::array<std::uint8_t, kVmkBytes>& key,
    const std::array<std::uint8_t, kVaultNonceBytes>& nonce,
    const std::vector<std::uint8_t>& aad,
    const std::array<std::uint8_t, kVaultTagBytes>& tag,
    std::vector<std::uint8_t>& plaintext
) {
    if (!sizes_fit_openssl(ciphertext, aad)) return false;

    plaintext.assign(ciphertext.size() + 16, 0);
    EVP_CIPHER_CTX* context = EVP_CIPHER_CTX_new();
    if (context == nullptr) return false;

    int written = 0;
    int total = 0;
    bool ok =
        EVP_DecryptInit_ex(context, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1 &&
        EVP_CIPHER_CTX_ctrl(
            context,
            EVP_CTRL_GCM_SET_IVLEN,
            static_cast<int>(nonce.size()),
            nullptr
        ) == 1 &&
        EVP_DecryptInit_ex(context, nullptr, nullptr, key.data(), nonce.data()) == 1 &&
        EVP_DecryptUpdate(
            context,
            nullptr,
            &written,
            aad.data(),
            static_cast<int>(aad.size())
        ) == 1 &&
        EVP_DecryptUpdate(
            context,
            plaintext.data(),
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
        ok = EVP_DecryptFinal_ex(context, plaintext.data() + total, &written) == 1;
        total += written;
    }
    EVP_CIPHER_CTX_free(context);

    if (!ok) {
        clear_bytes(plaintext);
        return false;
    }
    plaintext.resize(static_cast<std::size_t>(total));
    return true;
}
#endif

}  // namespace

bool encrypt_vault(
    const std::vector<std::uint8_t>& plaintext,
    const std::array<std::uint8_t, kVmkBytes>& vmk,
    const std::array<std::uint8_t, kVaultIdBytes>& vault_id,
    std::uint64_t generation,
    VaultEnvelope& envelope
) {
    std::array<std::uint8_t, kVaultNonceBytes> nonce{};
    if (!fill_random_nonce(nonce)) return false;
    return encrypt_vault_with_nonce(plaintext, vmk, vault_id, generation, nonce, envelope);
}

bool encrypt_vault_with_nonce(
    const std::vector<std::uint8_t>& plaintext,
    const std::array<std::uint8_t, kVmkBytes>& vmk,
    const std::array<std::uint8_t, kVaultIdBytes>& vault_id,
    std::uint64_t generation,
    const std::array<std::uint8_t, kVaultNonceBytes>& nonce,
    VaultEnvelope& envelope
) {
    std::vector<std::uint8_t> aad;
    if (!build_vault_aad(vault_id, generation, aad)) return false;

    VaultEnvelope candidate;
    candidate.vault_id = vault_id;
    candidate.generation = generation;
    candidate.nonce = nonce;
    if (!aes_gcm_encrypt(
            plaintext,
            vmk,
            nonce,
            aad,
            candidate.ciphertext,
            candidate.tag
        )) {
        return false;
    }

    envelope = std::move(candidate);
    return true;
}

bool decrypt_vault(
    const VaultEnvelope& envelope,
    const std::array<std::uint8_t, kVmkBytes>& vmk,
    std::vector<std::uint8_t>& plaintext
) {
    if (envelope.vault_format_version != kVaultFormatVersion ||
        envelope.storage_schema_version != kTargetStorageSchemaVersion) {
        return false;
    }

    std::vector<std::uint8_t> aad;
    if (!build_vault_aad(
            envelope.vault_id,
            envelope.generation,
            aad,
            envelope.vault_format_version,
            envelope.storage_schema_version
        )) {
        return false;
    }

    std::vector<std::uint8_t> candidate;
    if (!aes_gcm_decrypt(
            envelope.ciphertext,
            vmk,
            envelope.nonce,
            aad,
            envelope.tag,
            candidate
        )) {
        clear_bytes(candidate);
        candidate.clear();
        return false;
    }

    plaintext.swap(candidate);
    // After swap candidate owns the caller's previous output. Wipe that retired
    // buffer without changing the successful plaintext result.
    clear_bytes(candidate);
    candidate.clear();
    return true;
}

bool wrap_vmk_with_key_and_nonce(
    const std::array<std::uint8_t, kVmkBytes>& vmk,
    const std::array<std::uint8_t, kVmkBytes>& wrapping_key,
    const std::array<std::uint8_t, kVaultIdBytes>& vault_id,
    const std::array<std::uint8_t, kVaultNonceBytes>& nonce,
    VmkWrapEnvelope& envelope
) {
    std::vector<std::uint8_t> aad;
    if (!build_vmk_wrap_aad(vault_id, aad)) return false;

    std::vector<std::uint8_t> plaintext(vmk.begin(), vmk.end());
    std::vector<std::uint8_t> ciphertext;
    std::array<std::uint8_t, kVaultTagBytes> tag{};
    const bool ok = aes_gcm_encrypt(
        plaintext,
        wrapping_key,
        nonce,
        aad,
        ciphertext,
        tag
    );
    clear_bytes(plaintext);
    plaintext.clear();
    if (!ok || ciphertext.size() != kVmkBytes) {
        clear_bytes(ciphertext);
        ciphertext.clear();
        return false;
    }

    VmkWrapEnvelope candidate;
    candidate.vault_id = vault_id;
    candidate.nonce = nonce;
    std::copy(ciphertext.begin(), ciphertext.end(), candidate.ciphertext.begin());
    candidate.tag = tag;
    clear_bytes(ciphertext);
    ciphertext.clear();

    envelope = candidate;
    return true;
}

bool unwrap_vmk_with_key(
    const VmkWrapEnvelope& envelope,
    const std::array<std::uint8_t, kVmkBytes>& wrapping_key,
    std::array<std::uint8_t, kVmkBytes>& vmk
) {
    if (envelope.package_version != kRecoveryPackageVersion ||
        envelope.wrap_version != kVmkWrapVersion) {
        return false;
    }

    std::vector<std::uint8_t> aad;
    if (!build_vmk_wrap_aad(
            envelope.vault_id,
            aad,
            envelope.package_version,
            envelope.wrap_version
        )) {
        return false;
    }

    std::vector<std::uint8_t> ciphertext(
        envelope.ciphertext.begin(),
        envelope.ciphertext.end()
    );
    std::vector<std::uint8_t> plaintext;
    if (!aes_gcm_decrypt(
            ciphertext,
            wrapping_key,
            envelope.nonce,
            aad,
            envelope.tag,
            plaintext
        ) || plaintext.size() != kVmkBytes) {
        clear_bytes(plaintext);
        plaintext.clear();
        clear_bytes(ciphertext);
        ciphertext.clear();
        return false;
    }

    std::array<std::uint8_t, kVmkBytes> candidate{};
    std::copy(plaintext.begin(), plaintext.end(), candidate.begin());
    clear_bytes(plaintext);
    plaintext.clear();
    clear_bytes(ciphertext);
    ciphertext.clear();
    vmk = candidate;
    secure_zero_memory(candidate.data(), candidate.size());
    return true;
}

}  // namespace m5auth::vault
