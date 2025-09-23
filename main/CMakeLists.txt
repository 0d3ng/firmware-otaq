idf_component_register(SRCS "main.c" "ota_updater.c" "sensor_task.c" "wifi_connect.c" "mqtt_app.c"
                       REQUIRES spi_flash nvs_flash monocypher mqtt esp_http_client esp_wifi esp_https_ota app_update miniz
                       INCLUDE_DIRS ".")