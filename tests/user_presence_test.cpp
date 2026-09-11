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

    // An input event that predates the request cannot authorize it.
    assert(!gate.confirm_current(1'100, 7));
    assert(gate.state() == PresenceState::kAwaiting);
    assert(gate.confirm_current(1'101, 8));
    assert(gate.state() == PresenceState::kConfirmed);
    assert(gate.consume_confirmation(first, 1'102));
    assert(gate.state() == PresenceState::kIdle);

    // A superseding attempt invalidates the previous attempt and baseline.
    assert(gate.begin(PresenceOperation::kRecovery, first, 2'000, 10));
    assert(gate.begin(PresenceOperation::kBrowserReplacement, second, 2'100, 11));
    assert(!gate.confirm_current(2'101, 11));
    assert(gate.confirm_current(2'102, 12));
    assert(!gate.consume_confirmation(first, 2'103));
    assert(gate.state() == PresenceState::kIdle);

    // Confirmation itself expires with the attempt and cannot be reused.
    assert(gate.begin(PresenceOperation::kVmkRekey, second, 5'000, 20));
    assert(gate.confirm_current(5'001, 21));
    assert(gate.expire(35'000));
    assert(gate.state() == PresenceState::kIdle);
    assert(!gate.consume_confirmation(second, 35'001));

    assert(gate.begin(PresenceOperation::kInitialProvisioning, first, 50'000, 30));
    gate.cancel();
    assert(!gate.active());

    return 0;
}
