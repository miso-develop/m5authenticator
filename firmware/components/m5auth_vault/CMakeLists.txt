idf_component_register(
    SRCS "vault_format.cpp" "vault_crypto.cpp"
    INCLUDE_DIRS "include"
    REQUIRES mbedtls esp_hw_support
)
