#include <cassert>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

#include "m5auth/device/sticks3/ui_model.hpp"

namespace {

m5auth::storage::AccountMetadata account(
    std::uint32_t id,
    std::uint16_t order,
    std::string issuer,
    std::string account_name,
    std::string display_name = {}
) {
    return m5auth::storage::AccountMetadata{
        .id = id,
        .order = order,
        .issuer = std::move(issuer),
        .account = std::move(account_name),
        .display_name = std::move(display_name),
    };
}

}  // namespace

int main() {
    using m5auth::device::sticks3::UiModel;
    using m5auth::device::sticks3::account_display_label;

    assert(account_display_label(account(1, 0, "Issuer", "account", "User")) == "User");
    assert(account_display_label(account(1, 0, "Issuer", "account")) == "Issuer");
    assert(account_display_label(account(1, 0, "", "account")) == "account");

    UiModel model;
    assert(model.account_count() == 0);
    assert(model.selected_account() == nullptr);
    assert(!model.reveal(123456, 100));

    std::vector<m5auth::storage::AccountMetadata> accounts;
    accounts.push_back(account(2, 1, "Second", "two"));
    accounts.push_back(account(1, 0, "First", "one"));
    assert(model.update_accounts(std::move(accounts), 2));
    assert(model.selected_id() == 2);
    assert(model.selected_position() == 2);
    assert(model.account_count() == 2);

    assert(model.select_next());
    assert(model.selected_id() == 1);
    assert(model.selected_position() == 1);
    assert(model.select_previous());
    assert(model.selected_id() == 2);

    assert(model.reveal(42, 1'000));
    assert(model.reveal_active());
    assert(model.revealed_code() == 42);
    assert(!model.expire(10'999));
    assert(model.reveal_active());
    assert(model.expire(11'000));
    assert(!model.reveal_active());
    assert(model.revealed_code() == 0);

    assert(model.reveal(654321, 20'000));
    std::vector<m5auth::storage::AccountMetadata> renamed;
    renamed.push_back(account(2, 0, "Second", "two", "Renamed"));
    renamed.push_back(account(1, 1, "First", "one"));
    assert(model.update_accounts(std::move(renamed), 1));
    assert(model.selected_id() == 2);
    assert(model.selected_position() == 1);
    assert(!model.reveal_active());
    assert(model.revealed_code() == 0);

    std::vector<m5auth::storage::AccountMetadata> replacement;
    replacement.push_back(account(7, 0, "Only", "seven"));
    assert(model.update_accounts(std::move(replacement), 7));
    assert(model.selected_id() == 7);
    assert(model.account_count() == 1);
    assert(!model.select_next());
    assert(!model.select_previous());

    std::vector<m5auth::storage::AccountMetadata> max_accounts;
    for (std::uint32_t index = 0; index < 32; ++index) {
        max_accounts.push_back(account(
            index + 1,
            static_cast<std::uint16_t>(index),
            "Issuer",
            "account"
        ));
    }
    assert(model.update_accounts(std::move(max_accounts), 1));
    assert(model.selected_id() == 1);
    assert(model.account_count() == 32);
    assert(model.select_previous());
    assert(model.selected_id() == 32);
    assert(model.select_next());
    assert(model.selected_id() == 1);

    assert(model.update_accounts({}, 0));
    assert(model.selected_id() == 0);
    assert(model.selected_account() == nullptr);
    assert(model.account_count() == 0);

    return 0;
}
