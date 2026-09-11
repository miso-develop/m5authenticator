idf_component_register(
    SRCS "protocol.cpp" "session_binding_v2.cpp" "session_protocol_v2.cpp"
    INCLUDE_DIRS "include"
    REQUIRES m5auth_core m5auth_session m5auth_storage m5auth_time json
)
