#include "m5auth/device/sticks3/canonical_device.hpp"

#include "M5Unified.h"

namespace m5auth::device::sticks3 {

void initialize() {
    auto config = M5.config();

    // M5Authenticator has no audio feature. Keep the StickS3 audio path off so
    // the ES8311/AW8737 chain is not needlessly powered during USB operation.
    config.internal_spk = false;
    config.internal_mic = false;
    M5.begin(config);

    // Remain fail-silent even if a future library/default change initializes
    // the speaker path despite the configuration above.
    M5.Speaker.end();

    M5.Display.setRotation(1);
    M5.Display.clear();
    M5.Display.setTextSize(2);
    M5.Display.setTextColor(0xffff, 0x0000);
    M5.Display.setTextWrap(false);
    M5.Display.setCursor(0, 0);
    M5.Display.println("M5 Authenticator");
    M5.Display.println("Starting...");
}

}  // namespace m5auth::device::sticks3
