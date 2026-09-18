#include <cassert>
#include <cstdint>
#include <fstream>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include "m5auth/device/sticks3/label_scroll_state.hpp"
#include "m5auth/device/sticks3/totp_validity.hpp"
#include "m5auth/device/sticks3/ui_palette.hpp"
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

std::vector<m5auth::storage::AccountMetadata> make_max_accounts() {
    std::vector<m5auth::storage::AccountMetadata> accounts;
    for (std::uint32_t index = 0; index < 32; ++index) {
        accounts.push_back(account(
            index + 1,
            static_cast<std::uint16_t>(index),
            "Issuer",
            "account"
        ));
    }
    return accounts;
}

std::string read_text(const char* path) {
    std::ifstream input(path);
    assert(input.good());
    std::ostringstream buffer;
    buffer << input.rdbuf();
    return buffer.str();
}

}  // namespace

int main() {
    using m5auth::device::sticks3::UiModel;
    using m5auth::device::sticks3::account_display_label;
    using m5auth::device::sticks3::label_scroll::cycle_offset_px;
    using m5auth::device::sticks3::label_scroll::dwell_elapsed;
    using m5auth::device::sticks3::label_scroll::on_screen_hidden_changed;
    using m5auth::device::sticks3::label_scroll::reset;
    using m5auth::device::sticks3::label_scroll::update_offset;
    using m5auth::device::sticks3::totp_validity::from_unix_seconds;
    using m5auth::device::sticks3::totp_validity::same_period;
    using namespace m5auth::device::sticks3::ui_palette;
    using m5auth::session::AttemptId;
    using m5auth::session::PresenceOperation;

    // Issue #176: visual accents are stable presentation categories and remain
    // distinct from the existing semantic status colors.
    assert(kProductTitle == 0x1c9f);
    assert(kConfirmationAction == 0x07ff);
    assert(kProductTitle != kConfirmationAction);
    assert(kProductTitle != 0x07e0);
    assert(kProductTitle != 0xffe0);
    assert(kProductTitle != 0xf800);
    assert(kConfirmationAction != 0x07e0);
    assert(kConfirmationAction != 0xffe0);
    assert(kConfirmationAction != 0xf800);

    assert(account_display_label(account(1, 0, "Issuer", "account", "User")) == "User");
    assert(account_display_label(account(1, 0, "Issuer", "account")) == "Issuer");
    assert(account_display_label(account(1, 0, "", "account")) == "account");

    // Issue #148: the validity indicator follows RFC6238's 30-second period,
    // independent of the 10-second reveal lifetime maintained by UiModel.
    const auto validity_0 = from_unix_seconds(0);
    const auto validity_29 = from_unix_seconds(29);
    const auto validity_30 = from_unix_seconds(30);
    const auto validity_59 = from_unix_seconds(59);
    const auto validity_60 = from_unix_seconds(60);
    assert(validity_0.period_index == 0 && validity_0.seconds_remaining == 30);
    assert(validity_29.period_index == 0 && validity_29.seconds_remaining == 1);
    assert(validity_30.period_index == 1 && validity_30.seconds_remaining == 30);
    assert(validity_59.period_index == 1 && validity_59.seconds_remaining == 1);
    assert(validity_60.period_index == 2 && validity_60.seconds_remaining == 30);
    assert(same_period(validity_0, validity_29));
    assert(!same_period(validity_29, validity_30));

    // Issue #148 runtime/display contracts that are practical to verify on the
    // host: rollover must blank the old OTP before drawing new-period validity,
    // rollover refresh must not move the 10-second deadline, failure paths must
    // hide stale OTP, and semantic status categories must remain stable.
    const std::string canonical_ui = read_text(
        "firmware/components/m5auth_device_sticks3/canonical_device.cpp"
    );

    const std::size_t render_region_start = canonical_ui.find(
        "void CanonicalUiController::render_reveal_region()"
    );
    const std::size_t render_region_end = canonical_ui.find(
        "\nvoid CanonicalUiController::render()",
        render_region_start
    );
    assert(render_region_start != std::string::npos);
    assert(render_region_end != std::string::npos);
    const std::string render_region = canonical_ui.substr(
        render_region_start,
        render_region_end - render_region_start
    );
    const std::size_t erase_old_otp = render_region.find("kOtpY");
    const std::size_t draw_new_validity = render_region.find("render_reveal_validity();");
    const std::size_t draw_new_otp = render_region.find("draw_otp(revealed_code_);");
    assert(erase_old_otp != std::string::npos);
    assert(draw_new_validity != std::string::npos);
    assert(draw_new_otp != std::string::npos);
    assert(erase_old_otp < draw_new_validity);
    assert(draw_new_validity < draw_new_otp);
    assert(render_region.find("M5.Display.clear();") == std::string::npos);

    const std::size_t refresh_start = canonical_ui.find(
        "bool CanonicalUiController::refresh_revealed_totp()"
    );
    const std::size_t refresh_end = canonical_ui.find(
        "\nvoid CanonicalUiController::reveal_selected",
        refresh_start
    );
    assert(refresh_start != std::string::npos);
    assert(refresh_end != std::string::npos);
    const std::string refresh_reveal = canonical_ui.substr(
        refresh_start,
        refresh_end - refresh_start
    );
    assert(refresh_reveal.find("reveal_deadline_ms_ =") == std::string::npos);
    assert(refresh_reveal.find("current_unix_seconds") != std::string::npos);
    assert(refresh_reveal.find("same_period") != std::string::npos);

    const std::size_t run_start = canonical_ui.find("void CanonicalUiController::run()");
    assert(run_start != std::string::npos);
    const std::string run_loop = canonical_ui.substr(run_start);
    const std::size_t readiness_guard = run_loop.find(
        "readiness != time::Readiness::kReady || now_ms >= reveal_deadline_ms_"
    );
    assert(readiness_guard != std::string::npos);
    assert(run_loop.find("hide_reveal();", readiness_guard) != std::string::npos);

    const std::size_t trusted_time_failure = run_loop.find(
        "if (!time_service_.current_unix_seconds(&current_unix_seconds))"
    );
    assert(trusted_time_failure != std::string::npos);
    const std::size_t trusted_time_else = run_loop.find("} else {", trusted_time_failure);
    assert(trusted_time_else != std::string::npos);
    const std::string trusted_time_failure_block = run_loop.substr(
        trusted_time_failure,
        trusted_time_else - trusted_time_failure
    );
    assert(trusted_time_failure_block.find("hide_reveal();") != std::string::npos);

    const std::size_t rollover_start = run_loop.find(
        "if (current_validity.period_index != revealed_period_index_)"
    );
    const std::size_t rollover_end = run_loop.find("} else if (", rollover_start);
    assert(rollover_start != std::string::npos);
    assert(rollover_end != std::string::npos);
    const std::string rollover = run_loop.substr(
        rollover_start,
        rollover_end - rollover_start
    );
    assert(rollover.find("refresh_revealed_totp()") != std::string::npos);
    assert(rollover.find("hide_reveal();") != std::string::npos);
    assert(rollover.find("reveal_deadline_ms_ =") == std::string::npos);

    assert(canonical_ui.find("constexpr std::uint16_t kColorGood = 0x07e0;") != std::string::npos);
    assert(canonical_ui.find("constexpr std::uint16_t kColorAttention = 0xffe0;") != std::string::npos);
    assert(canonical_ui.find("constexpr std::uint16_t kColorError = 0xf800;") != std::string::npos);
    assert(canonical_ui.find("case time::Readiness::kReady: return kColorGood;") != std::string::npos);
    assert(canonical_ui.find("case time::Readiness::kNotSynced: return kColorAttention;") != std::string::npos);
    assert(canonical_ui.find("case time::Readiness::kStale: return kColorError;") != std::string::npos);
    assert(canonical_ui.find("case vault_runtime::State::kUnlocked: return kColorGood;") != std::string::npos);
    assert(canonical_ui.find("case vault_runtime::State::kLocked:\n        case vault_runtime::State::kUnprovisioned:\n            return kColorAttention;") != std::string::npos);
    assert(canonical_ui.find("case vault_runtime::State::kReprovisionRequired:\n        case vault_runtime::State::kError:\n            return kColorError;") != std::string::npos);

    // Issue #139: clipped labels repeat a bounded monotonic cycle:
    // start dwell -> scroll -> end dwell -> reset -> start dwell -> repeat.
    constexpr std::uint64_t initial_dwell_ms = 2'000;
    constexpr std::uint64_t end_dwell_ms = 2'000;
    constexpr std::uint64_t step_ms = 40;
    constexpr int step_px = 1;
    constexpr int max_offset_px = 12;
    std::uint64_t label_scroll_epoch_ms = 1'000;
    int label_scroll_offset_px = 0;
    bool storage_error = false;

    reset(label_scroll_epoch_ms, &label_scroll_epoch_ms, &label_scroll_offset_px);
    assert(!dwell_elapsed(storage_error, label_scroll_epoch_ms, 2'999, initial_dwell_ms));
    assert(dwell_elapsed(storage_error, label_scroll_epoch_ms, 3'000, initial_dwell_ms));
    assert(cycle_offset_px(
        storage_error,
        label_scroll_epoch_ms,
        2'999,
        initial_dwell_ms,
        step_ms,
        step_px,
        max_offset_px,
        end_dwell_ms
    ) == 0);
    assert(cycle_offset_px(
        storage_error,
        label_scroll_epoch_ms,
        3'040,
        initial_dwell_ms,
        step_ms,
        step_px,
        max_offset_px,
        end_dwell_ms
    ) == 1);
    assert(cycle_offset_px(
        storage_error,
        label_scroll_epoch_ms,
        3'480,
        initial_dwell_ms,
        step_ms,
        step_px,
        max_offset_px,
        end_dwell_ms
    ) == max_offset_px);
    assert(cycle_offset_px(
        storage_error,
        label_scroll_epoch_ms,
        5'479,
        initial_dwell_ms,
        step_ms,
        step_px,
        max_offset_px,
        end_dwell_ms
    ) == max_offset_px);
    assert(cycle_offset_px(
        storage_error,
        label_scroll_epoch_ms,
        5'480,
        initial_dwell_ms,
        step_ms,
        step_px,
        max_offset_px,
        end_dwell_ms
    ) == 0);
    assert(cycle_offset_px(
        storage_error,
        label_scroll_epoch_ms,
        7'479,
        initial_dwell_ms,
        step_ms,
        step_px,
        max_offset_px,
        end_dwell_ms
    ) == 0);
    assert(cycle_offset_px(
        storage_error,
        label_scroll_epoch_ms,
        7'520,
        initial_dwell_ms,
        step_ms,
        step_px,
        max_offset_px,
        end_dwell_ms
    ) == 1);
    assert(cycle_offset_px(
        storage_error,
        label_scroll_epoch_ms,
        100'000,
        initial_dwell_ms,
        step_ms,
        step_px,
        0,
        end_dwell_ms
    ) == 0);

    // Storage-error hiding suspends progress; recovery starts a fresh visible dwell.
    assert(update_offset(storage_error, max_offset_px, &label_scroll_offset_px));
    assert(label_scroll_offset_px == max_offset_px);
    bool next_storage_error = true;
    assert(on_screen_hidden_changed(
        storage_error,
        next_storage_error,
        5'500,
        &label_scroll_epoch_ms,
        &label_scroll_offset_px
    ));
    storage_error = next_storage_error;
    assert(label_scroll_epoch_ms == 5'500);
    assert(label_scroll_offset_px == 0);
    assert(cycle_offset_px(
        storage_error,
        label_scroll_epoch_ms,
        10'000,
        initial_dwell_ms,
        step_ms,
        step_px,
        max_offset_px,
        end_dwell_ms
    ) == 0);
    assert(!update_offset(storage_error, 20, &label_scroll_offset_px));
    assert(label_scroll_offset_px == 0);

    next_storage_error = false;
    assert(on_screen_hidden_changed(
        storage_error,
        next_storage_error,
        10'000,
        &label_scroll_epoch_ms,
        &label_scroll_offset_px
    ));
    storage_error = next_storage_error;
    assert(label_scroll_epoch_ms == 10'000);
    assert(label_scroll_offset_px == 0);
    assert(cycle_offset_px(
        storage_error,
        label_scroll_epoch_ms,
        11'999,
        initial_dwell_ms,
        step_ms,
        step_px,
        max_offset_px,
        end_dwell_ms
    ) == 0);
    assert(cycle_offset_px(
        storage_error,
        label_scroll_epoch_ms,
        12'040,
        initial_dwell_ms,
        step_ms,
        step_px,
        max_offset_px,
        end_dwell_ms
    ) == 1);
    // A stale caller timestamp cannot unsigned-underflow past the dwell.
    assert(cycle_offset_px(
        storage_error,
        20'000,
        19'999,
        initial_dwell_ms,
        step_ms,
        step_px,
        max_offset_px,
        end_dwell_ms
    ) == 0);

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

    assert(model.update_accounts(make_max_accounts(), 1));
    assert(model.selected_id() == 7);
    assert(model.account_count() == 32);

    UiModel boot_model;
    assert(boot_model.update_accounts(make_max_accounts(), 1));
    assert(boot_model.selected_id() == 1);
    assert(boot_model.account_count() == 32);
    assert(boot_model.select_previous());
    assert(boot_model.selected_id() == 32);
    assert(boot_model.select_next());
    assert(boot_model.selected_id() == 1);

    UiModel security_model;
    std::vector<m5auth::storage::AccountMetadata> security_accounts;
    security_accounts.push_back(account(2, 1, "Second", "two"));
    security_accounts.push_back(account(1, 0, "First", "one"));
    assert(security_model.update_accounts(std::move(security_accounts), 2));
    assert(security_model.reveal(123456, 50'000));

    AttemptId attempt{};
    attempt[0] = 0x42;
    assert(security_model.begin_unlock_request(
        PresenceOperation::kTrustedBrowserUnlock,
        attempt,
        50'100
    ));
    assert(security_model.unlock_request_active());
    assert(!security_model.reveal_active());
    const std::uint32_t selected_before_request = security_model.selected_id();
    assert(!security_model.select_next());
    assert(!security_model.select_previous());
    assert(!security_model.reveal(111111, 50'101));
    assert(security_model.selected_id() == selected_before_request);

    // A press observed before a post-request released baseline is rejected.
    security_model.observe_primary_button_state(true);
    assert(!security_model.primary_button_pressed(50'102));
    assert(!security_model.unlock_request_confirmed());
    security_model.observe_primary_button_state(false);
    security_model.observe_primary_button_state(false);
    security_model.observe_primary_button_state(true);
    assert(security_model.primary_button_pressed(50'103));
    assert(security_model.unlock_request_confirmed());
    assert(security_model.consume_unlock_confirmation(attempt, 50'104));
    assert(!security_model.unlock_request_active());
    assert(security_model.select_next());

    AttemptId expiring_attempt{};
    expiring_attempt[0] = 0x55;
    assert(security_model.begin_unlock_request(
        PresenceOperation::kBrowserReplacement,
        expiring_attempt,
        60'000
    ));
    assert(!security_model.expire_unlock_request(89'999));
    assert(security_model.expire_unlock_request(90'000));
    assert(!security_model.unlock_request_active());

    assert(model.update_accounts({}, 0));
    assert(model.selected_id() == 0);
    assert(model.selected_account() == nullptr);
    assert(model.account_count() == 0);

    return 0;
}
