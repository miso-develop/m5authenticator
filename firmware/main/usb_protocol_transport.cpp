#include "usb_protocol_transport.hpp"

#include <algorithm>
#include <string>

#include "driver/usb_serial_jtag.h"
#include "freertos/FreeRTOS.h"

namespace m5auth::device_transport {
namespace {

constexpr std::size_t kUsbProtocolWriteChunkBytes = 512;
static_assert(kUsbProtocolWriteChunkBytes <= kUsbProtocolTxBufferBytes);

TickType_t timeout_ticks(std::uint32_t milliseconds) {
    const TickType_t ticks = pdMS_TO_TICKS(milliseconds);
    return ticks == 0 ? 1 : ticks;
}

}  // namespace

UsbProtocolTransport::~UsbProtocolTransport() {
    if (installed_) {
        (void)usb_serial_jtag_driver_uninstall();
    }
}

esp_err_t UsbProtocolTransport::install() {
    if (installed_) return ESP_OK;
    if (usb_serial_jtag_is_driver_installed()) return ESP_ERR_INVALID_STATE;

    usb_serial_jtag_driver_config_t config{};
    config.rx_buffer_size = kUsbProtocolRxBufferBytes;
    config.tx_buffer_size = kUsbProtocolTxBufferBytes;

    const esp_err_t status = usb_serial_jtag_driver_install(&config);
    if (status == ESP_OK) installed_ = true;
    return status;
}

int UsbProtocolTransport::read(void* buffer, std::size_t capacity) {
    if (!installed_ || buffer == nullptr || capacity == 0) return -1;
    const std::size_t bounded = std::min<std::size_t>(capacity, UINT32_MAX);
    return usb_serial_jtag_read_bytes(
        buffer,
        static_cast<std::uint32_t>(bounded),
        timeout_ticks(kUsbProtocolReadTimeoutMs)
    );
}

bool UsbProtocolTransport::write_frame(std::string_view response) {
    if (!installed_) return false;

    std::string frame;
    frame.reserve(response.size() + 1);
    frame.append(response.data(), response.size());
    frame.push_back('\n');

    std::size_t offset = 0;
    while (offset < frame.size()) {
        const std::size_t remaining = frame.size() - offset;
        const std::size_t chunk = std::min(remaining, kUsbProtocolWriteChunkBytes);
        const int written = usb_serial_jtag_write_bytes(
            frame.data() + offset,
            chunk,
            timeout_ticks(kUsbProtocolWriteTimeoutMs)
        );
        if (written <= 0 || static_cast<std::size_t>(written) != chunk) {
            std::fill(frame.begin(), frame.end(), '\0');
            return false;
        }
        offset += chunk;
    }

    const bool completed = usb_serial_jtag_wait_tx_done(
        timeout_ticks(kUsbProtocolWriteTimeoutMs)
    ) == ESP_OK;
    std::fill(frame.begin(), frame.end(), '\0');
    return completed;
}

bool UsbProtocolTransport::connected() const {
    return installed_ && usb_serial_jtag_is_connected();
}

void UsbProtocolTransport::establish_handshake() {
    phase_ = SessionPhase::kStrictPostHandshake;
}

void UsbProtocolTransport::fail_session() {
    phase_ = SessionPhase::kFaulted;
}

void UsbProtocolTransport::reset_pre_handshake() {
    phase_ = SessionPhase::kPreHandshake;
}

}  // namespace m5auth::device_transport
