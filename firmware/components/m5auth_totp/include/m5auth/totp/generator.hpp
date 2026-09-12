#pragma once

#include <cstdint>

#include "m5auth/time/time_service.hpp"
#include "m5auth/vault_runtime/runtime.hpp"

namespace m5auth::totp {

enum class GenerateResult {
    kOk,
    kNotSynced,
    kTimeStale,
    kAccountNotFound,
    kInvalidSecret,
    kCryptoError,
    kStorageError,
};

// Canonical Vault generator. The raw TOTP key is available only inside the
// Runtime synchronous credential callback and is never copied into UI state.
class VaultGenerator final {
public:
    VaultGenerator(vault_runtime::Runtime& runtime, time::TimeService& time_service);

    GenerateResult generate_for_credential(
        const vault_runtime::CredentialId& credential_id,
        std::uint32_t* code
    );

private:
    vault_runtime::Runtime& runtime_;
    time::TimeService& time_service_;
};

}  // namespace m5auth::totp
