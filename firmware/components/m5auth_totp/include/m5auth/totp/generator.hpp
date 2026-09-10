#pragma once

#include <cstdint>

#include "m5auth/storage/storage.hpp"
#include "m5auth/time/time_service.hpp"

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

class Generator {
public:
    Generator(storage::Store& store, time::TimeService& time_service);
    GenerateResult generate_for_account(std::uint32_t account_id, std::uint32_t* code) const;

private:
    storage::Store& store_;
    time::TimeService& time_service_;
};

}  // namespace m5auth::totp
