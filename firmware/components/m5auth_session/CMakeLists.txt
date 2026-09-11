idf_component_register(
    SRCS "session_crypto.cpp" "user_presence.cpp"
    INCLUDE_DIRS "include"
    REQUIRES mbedtls esp_hw_support
)
