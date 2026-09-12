#include "m5auth/vault_runtime/runtime.hpp"

#include <algorithm>
#include <utility>
#include <vector>

namespace m5auth::vault_runtime {

Status Runtime::list_credentials(std::vector<CredentialMetadata>* credentials) {
    if (credentials == nullptr) return Status::kInvalidArgument;
    credentials->clear();
    if (!initialized_) return Status::kNotReady;
    if (state_ != State::kUnlocked || !vmk_present_ || !has_vault_) {
        return Status::kLocked;
    }

    std::vector<std::uint8_t> encoded_plaintext;
    if (!vault::decrypt_vault(envelope_, vmk_, encoded_plaintext)) {
        if (!encoded_plaintext.empty()) secure_zero(encoded_plaintext.data(), encoded_plaintext.size());
        encoded_plaintext.clear();
        fatal_security_error();
        return Status::kAuthenticationFailed;
    }

    vault::VaultPlaintext plaintext;
    if (!vault::decode_plaintext(encoded_plaintext, plaintext)) {
        if (!encoded_plaintext.empty()) secure_zero(encoded_plaintext.data(), encoded_plaintext.size());
        encoded_plaintext.clear();
        wipe_plaintext(&plaintext);
        fatal_security_error();
        return Status::kCorrupt;
    }
    if (!encoded_plaintext.empty()) secure_zero(encoded_plaintext.data(), encoded_plaintext.size());
    encoded_plaintext.clear();

    // ESP-IDF production builds do not rely on C++ exception handling. Memory
    // exhaustion remains a process-level failure rather than creating an
    // exception-only security cleanup path that is absent on Device.
    credentials->reserve(plaintext.credentials.size());
    for (const auto& credential : plaintext.credentials) {
        CredentialMetadata metadata;
        metadata.credential_id = credential.credential_id;
        metadata.issuer = credential.issuer;
        metadata.account = credential.account;
        metadata.display_name = credential.display_name;
        metadata.manual_order = credential.manual_order;
        credentials->push_back(std::move(metadata));
    }
    std::stable_sort(
        credentials->begin(),
        credentials->end(),
        [](const CredentialMetadata& left, const CredentialMetadata& right) {
            return left.manual_order < right.manual_order;
        }
    );

    wipe_plaintext(&plaintext);
    return Status::kOk;
}

}  // namespace m5auth::vault_runtime
