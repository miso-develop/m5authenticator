#include <string>

namespace m5auth::provisioning {

std::string session_v2_message_too_large_response() {
    return R"({"v":2,"id":0,"ok":false,"error":{"code":"message_too_large"}})";
}

}  // namespace m5auth::provisioning
