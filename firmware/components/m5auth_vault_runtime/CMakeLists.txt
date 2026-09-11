idf_component_register(
    SRCS
        "runtime.cpp"
        "rekey.cpp"
        "nvs_persistence.cpp"
        "compatible_nvs_persistence.cpp"
    INCLUDE_DIRS "include"
    REQUIRES m5auth_vault nvs_flash
)
