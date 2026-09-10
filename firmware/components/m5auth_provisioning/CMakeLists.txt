idf_component_register(
    SRCS "protocol.cpp" "security_protocol.cpp"
    INCLUDE_DIRS "include"
    REQUIRES m5auth_core m5auth_storage m5auth_time json
)
