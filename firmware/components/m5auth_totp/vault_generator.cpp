#include "m5auth/totp/generator.hpp"

#include <span>

#include "m5auth/totp/totp.hpp"

namespace m5auth::totp {

VaultGenerator::VaultGenerator(
    vault_runtime::Runtime& runtime,
    time::TimeService& time_service
) : runtime_(runtime), time_service_(time_service) {}

GenerateResult VaultGenerator::generate_for_credential(
    const vault_runtime::CredentialId& credential_id,
    std::uint32_t* code
) {
    if (code == nullptr) return GenerateResult::kAccountNotFound;

    const time::Snapshot before_vault = time_service_.status();
    if (before_vault.readiness == time::Readiness::kNotSynced) {
        return GenerateResult::kNotSynced;
    }
    if (before_vault.readiness == time::Readiness::kStale) {
        return GenerateResult::kTimeStale;
    }

    GenerateResult result = GenerateResult::kStorageError;
    const vault_runtime::Status runtime_status = runtime_.with_credential(
        credential_id,
        [&](const vault::CredentialRecord& credential) {
            const time::Snapshot current_status = time_service_.status();
            if (current_status.readiness == time::Readiness::kNotSynced) {
                result = GenerateResult::kNotSynced;
                return vault_runtime::Status::kOk;
            }
            if (current_status.readiness == time::Readiness::kStale) {
                result = GenerateResult::kTimeStale;
                return vault_runtime::Status::kOk;
            }

            // Vault Format 1 currently exposes SHA1/6-digit/30-second TOTP in
            // the physical Device UI. Fail closed if a future writer persists
            // a framing variant not supported by this firmware surface.
            if (credential.algorithm != vault::TotpAlgorithm::kSha1 ||
                credential.digits != kDigits ||
                credential.period_seconds != kPeriodSeconds ||
                credential.secret.empty()) {
                result = GenerateResult::kInvalidSecret;
                return vault_runtime::Status::kOk;
            }

            std::uint64_t unix_seconds = 0;
            if (!time_service_.current_unix_seconds(&unix_seconds)) {
                result = GenerateResult::kTimeStale;
                return vault_runtime::Status::kOk;
            }

            std::uint32_t generated = 0;
            const CoreResult core = generate_raw(
                std::span<const std::uint8_t>(credential.secret.data(), credential.secret.size()),
                unix_seconds,
                &generated
            );
            switch (core) {
                case CoreResult::kOk:
                    *code = generated;
                    result = GenerateResult::kOk;
                    break;
                case CoreResult::kInvalidSecret:
                    result = GenerateResult::kInvalidSecret;
                    break;
                case CoreResult::kCryptoError:
                    result = GenerateResult::kCryptoError;
                    break;
            }
            vault_runtime::secure_zero(&generated, sizeof(generated));
            return vault_runtime::Status::kOk;
        }
    );

    if (runtime_status == vault_runtime::Status::kNotFound) {
        return GenerateResult::kAccountNotFound;
    }
    if (runtime_status != vault_runtime::Status::kOk) {
        return GenerateResult::kStorageError;
    }
    return result;
}

}  // namespace m5auth::totp
