idf_component_register(
    SRCS "app_main.cpp"
    INCLUDE_DIRS "."
    REQUIRES m5auth_core m5auth_provisioning m5auth_device_sticks3
)

execute_process(
    COMMAND git rev-parse --short=12 HEAD
    WORKING_DIRECTORY "${CMAKE_CURRENT_LIST_DIR}/../.."
    OUTPUT_VARIABLE M5AUTH_BUILD_COMMIT
    OUTPUT_STRIP_TRAILING_WHITESPACE
    ERROR_QUIET
)
if(NOT M5AUTH_BUILD_COMMIT)
    set(M5AUTH_BUILD_COMMIT "unknown")
endif()
target_compile_definitions(${COMPONENT_LIB} PRIVATE M5AUTH_BUILD_COMMIT="${M5AUTH_BUILD_COMMIT}")
