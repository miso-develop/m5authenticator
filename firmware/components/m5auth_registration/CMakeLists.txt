idf_component_register(
    SRCS "registration.cpp"
    INCLUDE_DIRS "include"
    REQUIRES m5auth_session m5auth_vault nvs_flash esp_hw_support
)
