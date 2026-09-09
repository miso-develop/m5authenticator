#include "m5auth/device/sticks3/device.hpp"

#include "M5Unified.h"

namespace m5auth::device::sticks3 {

void initialize() {
    auto config = M5.config();
    M5.begin(config);

    M5.Display.setRotation(1);
    M5.Display.setTextSize(1);
    M5.Display.setCursor(0, 0);
    M5.Display.println("M5 Authenticator");
    M5.Display.println("Provisioning ready");
}

}  // namespace m5auth::device::sticks3
