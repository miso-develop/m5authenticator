#pragma once

#include <cstdint>

#include "m5auth/storage/storage.hpp"
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

const char* generate_result_code(GenerateResult result);

// Legacy Schema 1 generator retained for native compatibility tests until #55
// removes the legacy app_main route.
class Generator {
public:
    Generator(storage::Store& store, time::TimeService& time_service);
    GenerateResult generate_for_account(std::uint32_t account_id, std::uint32_t* code) const;

private:
    storage::Store& store_;
    time::TimeService& time_service_;
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
