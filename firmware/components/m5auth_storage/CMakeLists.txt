idf_component_register(
    SRCS "storage.cpp" "state.cpp" "security_hmac.cpp" "security_api.cpp" "security_policy.cpp"
    INCLUDE_DIRS "include"
    PRIV_INCLUDE_DIRS "."
    REQUIRES m5auth_core nvs_flash nvs_sec_provider efuse esp_hw_support bootloader_support
)
