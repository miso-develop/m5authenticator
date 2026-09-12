idf_component_register(
    SRCS
        "release_device.cpp"
        "canonical_device.cpp"
    INCLUDE_DIRS "include"
    REQUIRES
        m5unified
        m5auth_session
        m5auth_time
        m5auth_totp
        m5auth_vault_runtime
        esp_timer
)
