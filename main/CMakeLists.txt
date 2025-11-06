idf_component_register(SRCS "ecdsa_verify_p384.c" "nvs_util.c" "ntp.c" "main.c" "ota_updater.c" "ota_control.c" "sensor_task.c" "wifi_connect.c" "mqtt_app.c" "battery_voltage.c" "ecdsa_verify_p256.c" "certs/fullchain.c" "ecdsa_verify_p256_esp32.c" "nvs_util.c"
                       REQUIRES spi_flash nvs_flash monocypher mqtt esp_http_client esp_wifi esp_https_ota app_update miniz lwip spiffs cjson dht esp_adc mbedtls
                       INCLUDE_DIRS "." "certs")

target_include_directories(${COMPONENT_TARGET} PRIVATE
    "$ENV{IDF_PATH}/components/spiffs/include"
    "$ENV{IDF_PATH}/components/lwip/include"
)