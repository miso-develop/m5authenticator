idf_component_register(
    SRCS "trusted_time.cpp" "time_service.cpp"
    INCLUDE_DIRS "include"
    REQUIRES m5auth_storage esp_event esp_netif esp_timer esp_wifi
)
