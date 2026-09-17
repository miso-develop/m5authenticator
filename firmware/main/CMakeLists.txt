idf_component_register(
    SRCS
        "app_main.cpp"
        "usb_protocol_transport.cpp"
    INCLUDE_DIRS "."
    REQUIRES
        esp_driver_usb_serial_jtag
        json
        m5auth_core
        m5auth_provisioning
        m5auth_device_sticks3
        m5auth_registration
        m5auth_session
        m5auth_time
        m5auth_totp
        m5auth_vault
        m5auth_vault_runtime
    PRIV_REQUIRES
        hal
)

option(
    M5AUTH_TIMING_DIAGNOSTICS
    "Enable reset-persistent RTC Device operation timing diagnostics for #86"
    OFF
)
if(M5AUTH_TIMING_DIAGNOSTICS)
    target_compile_definitions(${COMPONENT_LIB} PRIVATE M5AUTH_TIMING_DIAGNOSTICS=1)
endif()

if(M5AUTH_TEST_SCREEN_SNAPSHOT)
    target_compile_definitions(${COMPONENT_LIB} PRIVATE M5AUTH_TEST_SCREEN_SNAPSHOT=1)
endif()

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
