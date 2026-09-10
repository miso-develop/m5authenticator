idf_component_register(
    SRCS "totp_core.cpp" "totp_mbedtls.cpp" "generator.cpp"
    INCLUDE_DIRS "include"
    REQUIRES m5auth_storage m5auth_time mbedtls
)
