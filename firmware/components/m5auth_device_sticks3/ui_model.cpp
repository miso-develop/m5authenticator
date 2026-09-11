#include "m5auth/device/sticks3/ui_model.hpp"

#include <algorithm>
#include <iterator>
#include <limits>
#include <utility>

namespace m5auth::device::sticks3 {
namespace {

bool account_equal(
    const storage::AccountMetadata& left,
    const storage::AccountMetadata& right
) {
    return left.id == right.id &&
           left.order == right.order &&
           left.issuer == right.issuer &&
           left.account == right.account &&
           left.display_name == right.display_name;
}

}  // namespace

std::string account_display_label(const storage::AccountMetadata& account) {
    if (!account.display_name.empty()) return account.display_name;
    if (!account.issuer.empty()) return account.issuer;
    return account.account;
}

UiModel::~UiModel() {
    hide_reveal();
    presence_.cancel();
}

bool UiModel::accounts_equal(
    const std::vector<storage::AccountMetadata>& left,
    const std::vector<storage::AccountMetadata>& right
) {
    if (left.size() != right.size()) return false;
    for (std::size_t index = 0; index < left.size(); ++index) {
        if (!account_equal(left[index], right[index])) return false;
    }
    return true;
}

bool UiModel::contains(std::uint32_t id) const {
    if (id == 0) return false;
    return std::any_of(
        accounts_.begin(),
        accounts_.end(),
        [id](const storage::AccountMetadata& account) { return account.id == id; }
    );
}

bool UiModel::update_accounts(
    std::vector<storage::AccountMetadata> accounts,
    std::uint32_t preferred_id
) {
    std::sort(
        accounts.begin(),
        accounts.end(),
        [](const storage::AccountMetadata& left, const storage::AccountMetadata& right) {
            if (left.order != right.order) return left.order < right.order;
            return left.id < right.id;
        }
    );

    const bool account_snapshot_changed = !accounts_equal(accounts_, accounts);
    const std::uint32_t previous_selected = selected_id_;
    if (account_snapshot_changed) {
        hide_reveal();
        accounts_ = std::move(accounts);
    }

    if (!contains(selected_id_)) {
        if (contains(preferred_id)) {
            selected_id_ = preferred_id;
        } else {
            selected_id_ = accounts_.empty() ? 0 : accounts_.front().id;
        }
    }

    return account_snapshot_changed || previous_selected != selected_id_;
}

bool UiModel::select_next() {
    if (presence_.active()) return false;
    bool changed = hide_reveal();
    if (accounts_.empty()) {
        selected_id_ = 0;
        return changed;
    }

    auto current = std::find_if(
        accounts_.begin(),
        accounts_.end(),
        [this](const storage::AccountMetadata& account) {
            return account.id == selected_id_;
        }
    );
    if (current == accounts_.end()) {
        selected_id_ = accounts_.front().id;
        return true;
    }

    const auto next = std::next(current) == accounts_.end()
        ? accounts_.begin()
        : std::next(current);
    if (next->id != selected_id_) {
        selected_id_ = next->id;
        changed = true;
    }
    return changed;
}

bool UiModel::select_previous() {
    if (presence_.active()) return false;
    bool changed = hide_reveal();
    if (accounts_.empty()) {
        selected_id_ = 0;
        return changed;
    }

    auto current = std::find_if(
        accounts_.begin(),
        accounts_.end(),
        [this](const storage::AccountMetadata& account) {
            return account.id == selected_id_;
        }
    );
    if (current == accounts_.end()) {
        selected_id_ = accounts_.front().id;
        return true;
    }

    const auto previous = current == accounts_.begin()
        ? std::prev(accounts_.end())
        : std::prev(current);
    if (previous->id != selected_id_) {
        selected_id_ = previous->id;
        changed = true;
    }
    return changed;
}

const storage::AccountMetadata* UiModel::selected_account() const {
    const auto found = std::find_if(
        accounts_.begin(),
        accounts_.end(),
        [this](const storage::AccountMetadata& account) {
            return account.id == selected_id_;
        }
    );
    return found == accounts_.end() ? nullptr : &*found;
}

std::uint32_t UiModel::selected_id() const {
    return selected_id_;
}

std::size_t UiModel::selected_position() const {
    for (std::size_t index = 0; index < accounts_.size(); ++index) {
        if (accounts_[index].id == selected_id_) return index + 1;
    }
    return 0;
}

std::size_t UiModel::account_count() const {
    return accounts_.size();
}

bool UiModel::reveal(std::uint32_t code, std::uint64_t now_ms) {
    if (presence_.active() || selected_account() == nullptr) return false;
    revealed_code_ = code;
    reveal_active_ = true;
    reveal_deadline_ms_ = now_ms >
            std::numeric_limits<std::uint64_t>::max() - kOtpRevealDurationMs
        ? std::numeric_limits<std::uint64_t>::max()
        : now_ms + kOtpRevealDurationMs;
    return true;
}

bool UiModel::expire(std::uint64_t now_ms) {
    if (!reveal_active_ || now_ms < reveal_deadline_ms_) return false;
    return hide_reveal();
}

bool UiModel::hide_reveal() {
    const bool was_active = reveal_active_ || revealed_code_ != 0 || reveal_deadline_ms_ != 0;
    reveal_active_ = false;
    revealed_code_ = 0;
    reveal_deadline_ms_ = 0;
    return was_active;
}

bool UiModel::reveal_active() const {
    return reveal_active_;
}

std::uint32_t UiModel::revealed_code() const {
    return revealed_code_;
}

bool UiModel::begin_unlock_request(
    session::PresenceOperation operation,
    const session::AttemptId& attempt_id,
    std::uint64_t now_ms
) {
    const bool reveal_was_visible = hide_reveal();
    (void)presence_.begin(
        operation,
        attempt_id,
        now_ms,
        button_press_generation_
    );
    return reveal_was_visible || presence_.active();
}

bool UiModel::expire_unlock_request(std::uint64_t now_ms) {
    return presence_.expire(now_ms);
}

void UiModel::cancel_unlock_request() {
    presence_.cancel();
}

bool UiModel::unlock_request_active() const {
    return presence_.active();
}

bool UiModel::unlock_request_confirmed() const {
    return presence_.state() == session::PresenceState::kConfirmed;
}

session::PresenceOperation UiModel::unlock_request_operation() const {
    return presence_.operation();
}

bool UiModel::primary_button_pressed(std::uint64_t now_ms) {
    if (button_press_generation_ != std::numeric_limits<std::uint64_t>::max()) {
        ++button_press_generation_;
    }
    if (!presence_.active()) return false;
    return presence_.confirm_current(now_ms, button_press_generation_);
}

bool UiModel::consume_unlock_confirmation(
    const session::AttemptId& attempt_id,
    std::uint64_t now_ms
) {
    return presence_.consume_confirmation(attempt_id, now_ms);
}

}  // namespace m5auth::device::sticks3
