idf_component_register(SRCS "ntp.c" "main.c" "ota_updater.c" "sensor_task.c" "wifi_connect.c" "mqtt_app.c"
                       REQUIRES spi_flash nvs_flash monocypher mqtt esp_http_client esp_wifi esp_https_ota app_update miniz lwip spiffs cjson
                       INCLUDE_DIRS ".")

target_include_directories(${COMPONENT_TARGET} PRIVATE
    "$ENV{IDF_PATH}/components/spiffs/include"
    "$ENV{IDF_PATH}/components/lwip/include"
)