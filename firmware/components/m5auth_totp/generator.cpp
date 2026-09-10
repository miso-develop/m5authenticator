#include "m5auth/totp/generator.hpp"

#include "m5auth/totp/totp.hpp"

namespace m5auth::totp {

const char* generate_result_code(GenerateResult result) {
    switch (result) {
        case GenerateResult::kOk: return "ok";
        case GenerateResult::kNotSynced: return "time_not_synced";
        case GenerateResult::kTimeStale: return "time_stale";
        case GenerateResult::kAccountNotFound: return "account_not_found";
        case GenerateResult::kInvalidSecret: return "invalid_totp_secret";
        case GenerateResult::kCryptoError: return "totp_crypto_error";
        case GenerateResult::kStorageError: return "storage_error";
    }
    return "totp_error";
}

Generator::Generator(storage::Store& store, time::TimeService& time_service)
    : store_(store), time_service_(time_service) {}

GenerateResult Generator::generate_for_account(
    std::uint32_t account_id,
    std::uint32_t* code
) const {
    if (account_id == 0 || code == nullptr) return GenerateResult::kAccountNotFound;
    const time::Snapshot time_status = time_service_.status();
    if (time_status.readiness == time::Readiness::kNotSynced) return GenerateResult::kNotSynced;
    if (time_status.readiness == time::Readiness::kStale) return GenerateResult::kTimeStale;

    std::uint64_t unix_seconds = 0;
    if (!time_service_.current_unix_seconds(&unix_seconds)) return GenerateResult::kTimeStale;

    GenerateResult result = GenerateResult::kStorageError;
    const storage::Status storage_status = store_.with_account_secret(
        account_id,
        [&](std::string_view secret) {
            std::uint32_t generated = 0;
            const CoreResult core = generate(secret, unix_seconds, &generated);
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
            return storage::Status::kOk;
        }
    );
    if (storage_status == storage::Status::kNotFound) return GenerateResult::kAccountNotFound;
    if (storage_status != storage::Status::kOk) return GenerateResult::kStorageError;
    return result;
}

}  // namespace m5auth::totp
