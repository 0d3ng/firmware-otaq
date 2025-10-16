idf_component_register(SRCS "ntp.c" "main.c" "ota_updater.c" "sensor_task.c" "wifi_connect.c" "mqtt_app.c" "battery_voltage.c"
                       REQUIRES spi_flash nvs_flash monocypher mqtt esp_http_client esp_wifi esp_https_ota app_update miniz lwip spiffs cjson dht esp_adc
                       INCLUDE_DIRS ".")

target_include_directories(${COMPONENT_TARGET} PRIVATE
    "$ENV{IDF_PATH}/components/spiffs/include"
    "$ENV{IDF_PATH}/components/lwip/include"
)

add_compile_definitions(
    CONFIG_FREERTOS_USE_TRACE_FACILITY=1
    CONFIG_FREERTOS_USE_STATS_FORMATTING_FUNCTIONS=1
)

