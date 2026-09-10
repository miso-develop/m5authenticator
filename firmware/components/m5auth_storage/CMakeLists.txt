idf_component_register(
    SRCS "storage.cpp" "state.cpp"
    INCLUDE_DIRS "include"
    PRIV_INCLUDE_DIRS "."
    REQUIRES m5auth_core nvs_flash
)
