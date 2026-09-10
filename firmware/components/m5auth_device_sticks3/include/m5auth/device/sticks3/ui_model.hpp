#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "m5auth/storage/storage.hpp"

namespace m5auth::device::sticks3 {

inline constexpr std::uint64_t kOtpRevealDurationMs = 10'000;

std::string account_display_label(const storage::AccountMetadata& account);

class UiModel {
public:
    ~UiModel();

    bool update_accounts(
        std::vector<storage::AccountMetadata> accounts,
        std::uint32_t preferred_id
    );

    bool select_next();
    bool select_previous();

    const storage::AccountMetadata* selected_account() const;
    std::uint32_t selected_id() const;
    std::size_t selected_position() const;
    std::size_t account_count() const;

    bool reveal(std::uint32_t code, std::uint64_t now_ms);
    bool expire(std::uint64_t now_ms);
    bool hide_reveal();
    bool reveal_active() const;
    std::uint32_t revealed_code() const;

private:
    static bool accounts_equal(
        const std::vector<storage::AccountMetadata>& left,
        const std::vector<storage::AccountMetadata>& right
    );
    bool contains(std::uint32_t id) const;

    std::vector<storage::AccountMetadata> accounts_;
    std::uint32_t selected_id_{0};
    bool reveal_active_{false};
    std::uint32_t revealed_code_{0};
    std::uint64_t reveal_deadline_ms_{0};
};

}  // namespace m5auth::device::sticks3
