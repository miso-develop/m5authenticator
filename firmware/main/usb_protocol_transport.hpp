#pragma once

#include <cstddef>
#include <cstdint>
#include <string_view>

#include "esp_err.h"

namespace m5auth::device_transport {

inline constexpr std::size_t kUsbProtocolRxBufferBytes = 1024;
inline constexpr std::size_t kUsbProtocolTxBufferBytes = 1024;
inline constexpr std::uint32_t kUsbProtocolReadTimeoutMs = 20;
inline constexpr std::uint32_t kUsbProtocolWriteTimeoutMs = 250;

enum class SessionPhase {
    kPreHandshake,
    kStrictPostHandshake,
    kFaulted,
};

class UsbProtocolTransport final {
public:
    UsbProtocolTransport() = default;
    ~UsbProtocolTransport();

    UsbProtocolTransport(const UsbProtocolTransport&) = delete;
    UsbProtocolTransport& operator=(const UsbProtocolTransport&) = delete;

    esp_err_t install();
    int read(void* buffer, std::size_t capacity);
    bool write_frame(std::string_view response);
    bool connected() const;

    SessionPhase phase() const { return phase_; }
    bool strict_post_handshake() const {
        return phase_ == SessionPhase::kStrictPostHandshake;
    }
    bool faulted() const { return phase_ == SessionPhase::kFaulted; }

    void establish_handshake();
    void fail_session();
    void reset_pre_handshake();

private:
    bool installed_{false};
    SessionPhase phase_{SessionPhase::kPreHandshake};
};

}  // namespace m5auth::device_transport
