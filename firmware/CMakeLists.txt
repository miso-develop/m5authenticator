cmake_minimum_required(VERSION 3.16)

option(
    M5AUTH_TEST_SCREEN_SNAPSHOT
    "Enable test-only sanitized screen snapshot diagnostics for #117"
    OFF
)

include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(m5authenticator VERSION 1.0.1)
