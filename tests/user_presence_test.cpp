#include <cassert>
#include <cstdint>
#include <cstring>

#include "m5auth/session/session.hpp"

int main() {
    using namespace m5auth::session;

    assert(std::strcmp(presence_operation_text(PresenceOperation::kRecovery), "Recovery") == 0);
    assert(std::strcmp(presence_operation_text(PresenceOperation::kFactoryReset), "FACTORY RESET") == 0);

    AttemptId first{};
    first[0] = 0x11;
    AttemptId second{};
    second[0] = 0x22;

    // Existing baseline: neutral input must be established after begin(), the
    // input generation must advance, and confirmation is single-use.
    {
        UserPresenceGate gate;
        assert(gate.state() == PresenceState::kIdle);
        assert(gate.begin(PresenceOperation::kTrustedBrowserUnlock, first, 1'000, 7));
        assert(gate.active());
        assert(gate.state() == PresenceState::kAwaiting);
        assert(gate.expires_at_ms() == 31'000);

        gate.observe_input_state(false);
        gate.observe_input_state(true);
        assert(!gate.input_armed());
        assert(!gate.confirm_current(1'100, 8));
        assert(gate.state() == PresenceState::kAwaiting);

        gate.observe_input_state(false);
        assert(!gate.input_armed());
        gate.observe_input_state(false);
        assert(gate.input_armed());
        assert(!gate.confirm_current(1'101, 7));
        gate.observe_input_state(true);
        assert(gate.confirm_current(1'102, 9));
        assert(gate.state() == PresenceState::kConfirmed);
        assert(gate.consume_confirmation(first, 1'103));
        assert(gate.state() == PresenceState::kIdle);
        assert(!gate.consume_confirmation(first, 1'104));
    }

    // #114 regression 1: a prior input generation is only a baseline. A stale
    // generation consumes no authorization, and the sampled edge used with it
    // cannot later be upgraded by advancing only the generation counter.
    {
        UserPresenceGate gate;
        assert(gate.begin(PresenceOperation::kTrustedBrowserUnlock, first, 10'000, 100));
        gate.observe_input_state(false);
        gate.observe_input_state(false);
        assert(gate.input_armed());
        gate.observe_input_state(true);
        assert(!gate.confirm_current(10'001, 100));
        assert(gate.state() == PresenceState::kAwaiting);
        assert(!gate.confirm_current(10'002, 101));

        gate.observe_input_state(false);
        gate.observe_input_state(true);
        assert(gate.confirm_current(10'003, 101));
        assert(gate.consume_confirmation(first, 10'004));
    }

    // #114 regression 2: if A is already held when an attempt begins, the gate
    // must observe release/neutral first and then a new post-arm press.
    {
        UserPresenceGate gate;
        assert(gate.begin(PresenceOperation::kTrustedBrowserUnlock, first, 20'000, 200));
        gate.observe_input_state(true);
        gate.observe_input_state(true);
        assert(!gate.input_armed());
        assert(!gate.confirm_current(20'001, 201));

        gate.observe_input_state(false);
        assert(!gate.input_armed());
        gate.observe_input_state(false);
        assert(gate.input_armed());
        assert(!gate.confirm_current(20'002, 201));

        gate.observe_input_state(true);
        assert(gate.confirm_current(20'003, 202));
        assert(gate.consume_confirmation(first, 20'004));
    }

    // #114 regression 3: an externally stale wasPressed-equivalent signal must
    // not be enough on its own. A sampled press that is released before it is
    // consumed is stale too and must not authorize later.
    {
        UserPresenceGate gate;
        assert(gate.begin(PresenceOperation::kTrustedBrowserUnlock, first, 30'000, 300));
        gate.observe_input_state(false);
        gate.observe_input_state(false);
        assert(gate.input_armed());
        assert(!gate.confirm_current(30'001, 301));
        assert(gate.state() == PresenceState::kAwaiting);

        gate.observe_input_state(true);
        gate.observe_input_state(false);
        assert(!gate.confirm_current(30'002, 301));

        gate.observe_input_state(true);
        assert(gate.confirm_current(30'003, 301));
        assert(gate.consume_confirmation(first, 30'004));
    }

    // #114 regression 4a: cancel clears all presence state. A press/confirmation
    // associated with the cancelled attempt cannot carry into the next one.
    {
        UserPresenceGate gate;
        assert(gate.begin(PresenceOperation::kTrustedBrowserUnlock, first, 40'000, 400));
        gate.observe_input_state(false);
        gate.observe_input_state(false);
        gate.observe_input_state(true);
        assert(gate.confirm_current(40'001, 401));
        gate.cancel();
        assert(!gate.active());

        assert(gate.begin(PresenceOperation::kTrustedBrowserUnlock, second, 40'100, 401));
        assert(!gate.input_armed());
        assert(!gate.confirm_current(40'101, 402));
        gate.observe_input_state(false);
        gate.observe_input_state(false);
        gate.observe_input_state(true);
        assert(gate.confirm_current(40'102, 402));
        assert(gate.consume_confirmation(second, 40'103));
    }

    // #114 regression 4b: timeout has the same clearing semantics as cancel.
    {
        UserPresenceGate gate;
        assert(gate.begin(PresenceOperation::kTrustedBrowserUnlock, first, 50'000, 500));
        gate.observe_input_state(false);
        gate.observe_input_state(false);
        gate.observe_input_state(true);
        assert(gate.confirm_current(50'001, 501));
        assert(gate.expire(80'000));
        assert(gate.state() == PresenceState::kIdle);
        assert(!gate.consume_confirmation(first, 80'001));

        assert(gate.begin(PresenceOperation::kTrustedBrowserUnlock, second, 80'010, 501));
        assert(!gate.confirm_current(80'011, 502));
        gate.observe_input_state(false);
        gate.observe_input_state(false);
        gate.observe_input_state(true);
        assert(gate.confirm_current(80'012, 502));
        assert(gate.consume_confirmation(second, 80'013));
    }

    // #114 regression 5: beginning a superseding attempt invalidates a prior
    // confirmed attempt, and the old attempt ID cannot consume the new gate.
    {
        UserPresenceGate gate;
        assert(gate.begin(PresenceOperation::kRecovery, first, 90'000, 600));
        gate.observe_input_state(false);
        gate.observe_input_state(false);
        gate.observe_input_state(true);
        assert(gate.confirm_current(90'001, 601));
        assert(gate.state() == PresenceState::kConfirmed);

        assert(gate.begin(PresenceOperation::kBrowserReplacement, second, 90'100, 601));
        assert(gate.state() == PresenceState::kAwaiting);
        assert(!gate.consume_confirmation(first, 90'101));
        assert(gate.state() == PresenceState::kIdle);
    }

    // #114 regression 6: an ordinary fresh A press after neutral confirms
    // exactly once and only for the current attempt.
    {
        UserPresenceGate gate;
        assert(gate.begin(PresenceOperation::kFactoryReset, first, 100'000, 700));
        assert(gate.operation() == PresenceOperation::kFactoryReset);
        gate.observe_input_state(false);
        gate.observe_input_state(false);
        gate.observe_input_state(true);
        assert(gate.confirm_current(100'001, 701));
        assert(gate.consume_confirmation(first, 100'002));
        assert(!gate.consume_confirmation(first, 100'003));
        assert(!gate.confirm_current(100'004, 702));
    }

    // Gesture quarantine keeps the press used for security presence from later
    // becoming an account-navigation/reveal gesture.
    {
        PresenceGestureQuarantine quarantine;
        quarantine.begin(110'000, 500);
        assert(quarantine.active());
        quarantine.observe(true, false, 110'400);
        assert(quarantine.active());
        quarantine.observe(false, false, 110'450);
        assert(quarantine.active());
        quarantine.observe(false, false, 110'950);
        assert(quarantine.active());
        quarantine.observe(false, true, 110'951);
        assert(quarantine.active());
        quarantine.observe(false, false, 110'971);
        assert(!quarantine.active());
    }

    return 0;
}
