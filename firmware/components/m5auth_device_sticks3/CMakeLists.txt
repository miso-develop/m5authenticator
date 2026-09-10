idf_component_register(
    SRCS
        "device.cpp"
        "hardware_identity.cpp"
        "ui_model.cpp"
        "production_security.cpp"
    INCLUDE_DIRS "include"
    REQUIRES
        m5unified
        m5auth_storage
        m5auth_time
        m5auth_totp
        esp_timer
)
