#pragma once

#include <string>
#include <string_view>
#include <vector>

#include "m5auth/core/metadata.hpp"
#include "m5auth/storage/storage.hpp"
#include "m5auth/time/time_service.hpp"

namespace m5auth::provisioning {

inline constexpr std::size_t kMaxMessageBytes = 1024;

class Session {
public:
    Session(const core::DeviceMetadata& metadata, storage::Store& store, time::TimeService& time_service);
    ~Session();

    Session(const Session&) = delete;
    Session& operator=(const Session&) = delete;

    std::string handle_line(std::string_view line);

private:
    void clear_import();

    const core::DeviceMetadata& metadata_;
    storage::Store& store_;
    time::TimeService& time_service_;
    bool import_active_{false};
    bool import_validated_{false};
    std::vector<storage::AccountDraft> import_accounts_;
};

std::string message_too_large_response();

}  // namespace m5auth::provisioning
