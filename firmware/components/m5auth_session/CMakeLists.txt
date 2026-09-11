idf_component_register(
    SRCS "session_crypto.cpp" "session_protocol_v2.cpp" "user_presence.cpp"
    INCLUDE_DIRS "include"
    REQUIRES mbedtls esp_hw_support
)
