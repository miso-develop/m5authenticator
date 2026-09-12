#include <cassert>
#include <cstdint>

#include "m5auth/session/session.hpp"

int main() {
    using namespace m5auth::session;

    AttemptId first{};
    first[0] = 0x11;
    AttemptId second{};
    second[0] = 0x22;

    UserPresenceGate gate;
    assert(gate.state() == PresenceState::kIdle);
    assert(gate.begin(PresenceOperation::kTrustedBrowserUnlock, first, 1'000, 7));
    assert(gate.active());
    assert(gate.state() == PresenceState::kAwaiting);
    assert(gate.expires_at_ms() == 31'000);

    // A press that races the request before a post-request neutral baseline is
    // observed cannot authorize it, even when it receives a newer generation.
    gate.observe_input_state(false);  // one sample may have been stale
    gate.observe_input_state(true);
    assert(!gate.input_armed());
    assert(!gate.confirm_current(1'100, 8));
    assert(gate.state() == PresenceState::kAwaiting);

    // Two consecutive released samples after the request arm exactly the next
    // fresh press. The old/pre-request generation remains rejected.
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

    // A superseding attempt invalidates the previous attempt and neutral baseline.
    assert(gate.begin(PresenceOperation::kRecovery, first, 2'000, 10));
    gate.observe_input_state(false);
    gate.observe_input_state(false);
    assert(gate.input_armed());
    assert(gate.begin(PresenceOperation::kBrowserReplacement, second, 2'100, 11));
    assert(!gate.input_armed());
    assert(!gate.confirm_current(2'101, 12));
    gate.observe_input_state(false);
    gate.observe_input_state(false);
    gate.observe_input_state(true);
    assert(gate.confirm_current(2'102, 12));
    assert(!gate.consume_confirmation(first, 2'103));
    assert(gate.state() == PresenceState::kIdle);

    // Confirmation itself expires with the attempt and cannot be reused.
    assert(gate.begin(PresenceOperation::kVmkRekey, second, 5'000, 20));
    gate.observe_input_state(false);
    gate.observe_input_state(false);
    gate.observe_input_state(true);
    assert(gate.confirm_current(5'001, 21));
    assert(gate.expire(35'000));
    assert(gate.state() == PresenceState::kIdle);
    assert(!gate.consume_confirmation(second, 35'001));

    assert(gate.begin(PresenceOperation::kInitialProvisioning, first, 50'000, 30));
    gate.cancel();
    assert(!gate.active());

    // A confirmation gesture remains quarantined while held, through release,
    // and through M5Unified's delayed click-decision event. Only the following
    // no-event sample after the hold-threshold window restores normal actions.
    PresenceGestureQuarantine quarantine;
    quarantine.begin(60'000, 500);
    assert(quarantine.active());
    quarantine.observe(true, false, 60'400);   // held confirmation gesture
    assert(quarantine.active());
    quarantine.observe(false, false, 60'450);  // release observed
    assert(quarantine.active());
    quarantine.observe(false, false, 60'950);  // boundary is still quarantined
    assert(quarantine.active());
    quarantine.observe(false, true, 60'951);   // delayed single-click decision drained
    assert(quarantine.active());
    quarantine.observe(false, false, 60'971);  // next neutral poll can resume normal input
    assert(!quarantine.active());

    return 0;
}
