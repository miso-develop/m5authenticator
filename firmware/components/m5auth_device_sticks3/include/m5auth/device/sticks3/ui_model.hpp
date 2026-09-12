#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "m5auth/session/protocol_v2.hpp"
#include "m5auth/storage/storage.hpp"

namespace m5auth::device::sticks3 {

inline constexpr std::uint64_t kOtpRevealDurationMs = 10'000;

std::string account_display_label(const storage::AccountMetadata& account);

class UiModel final : public session::protocol_v2::PresenceBinding {
public:
    ~UiModel() override;

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

    bool begin_unlock_request(
        session::PresenceOperation operation,
        const session::AttemptId& attempt_id,
        std::uint64_t now_ms
    );
    bool expire_unlock_request(std::uint64_t now_ms);
    void cancel_unlock_request();
    bool unlock_request_active() const;
    bool unlock_request_confirmed() const;
    session::PresenceOperation unlock_request_operation() const;
    void observe_primary_button_state(bool pressed) { presence_.observe_input_state(pressed); }
    bool primary_button_pressed(std::uint64_t now_ms);
    bool consume_unlock_confirmation(
        const session::AttemptId& attempt_id,
        std::uint64_t now_ms
    );

    bool begin_presence(
        session::PresenceOperation operation,
        const session::AttemptId& attempt_id,
        std::uint64_t now_ms
    ) override {
        return begin_unlock_request(operation, attempt_id, now_ms);
    }
    bool consume_presence(
        const session::AttemptId& attempt_id,
        std::uint64_t now_ms
    ) override {
        return consume_unlock_confirmation(attempt_id, now_ms);
    }
    void cancel_presence() override { cancel_unlock_request(); }
    bool presence_confirmed() const override { return unlock_request_confirmed(); }

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
    std::uint64_t button_press_generation_{0};
    session::UserPresenceGate presence_;
};

}  // namespace m5auth::device::sticks3
