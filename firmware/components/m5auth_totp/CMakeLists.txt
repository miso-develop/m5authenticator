idf_component_register(
    SRCS
        "totp_core.cpp"
        "totp_mbedtls.cpp"
        "vault_generator.cpp"
    INCLUDE_DIRS "include"
    REQUIRES
        m5auth_time
        m5auth_vault_runtime
        mbedtls
)
