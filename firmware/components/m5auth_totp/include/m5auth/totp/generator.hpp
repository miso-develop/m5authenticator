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

struct GenerateMetadata {
    // Non-secret trusted-time sample used by the TOTP core. UI consumers may
    // derive only the RFC6238 period/countdown from this value; it is never
    // persisted or logged by the generator.
    std::uint64_t unix_seconds{0};
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
    GenerateResult generate_for_credential(
        const vault_runtime::CredentialId& credential_id,
        std::uint32_t* code,
        GenerateMetadata* metadata
    );

private:
    vault_runtime::Runtime& runtime_;
    time::TimeService& time_service_;
};

}  // namespace m5auth::totp
