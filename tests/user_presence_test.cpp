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

    assert(gate.begin(PresenceOperation::kFactoryReset, first, 3'000, 13));
    assert(gate.operation() == PresenceOperation::kFactoryReset);
    gate.observe_input_state(false);
    gate.observe_input_state(false);
    gate.observe_input_state(true);
    assert(gate.confirm_current(3'001, 14));
    assert(gate.consume_confirmation(first, 3'002));

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

    PresenceGestureQuarantine quarantine;
    quarantine.begin(60'000, 500);
    assert(quarantine.active());
    quarantine.observe(true, false, 60'400);
    assert(quarantine.active());
    quarantine.observe(false, false, 60'450);
    assert(quarantine.active());
    quarantine.observe(false, false, 60'950);
    assert(quarantine.active());
    quarantine.observe(false, true, 60'951);
    assert(quarantine.active());
    quarantine.observe(false, false, 60'971);
    assert(!quarantine.active());

    return 0;
}
