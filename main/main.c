#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "wifi_connect.h"
#include "mqtt_app.h"
#include "ota_updater.h"
#include "sensor_task.h"
#include "ntp.h"
#include "ecdsa_verify_p256.h"
#include "ecdsa_verify_p384.h"
#include "ecdsa_verify_p256_esp32.h"
#include "nvs_util.h"

static const char *TAG = "main_app";

void app_main(void)
{
    printf("Running firmware version: %s\n", FIRMWARE_VERSION);
    ESP_LOGI(TAG, "Starting system...");
    uint64_t boot_end_time = esp_timer_get_time();
    ESP_LOGI(TAG, "Boot end time: %.2f ms", (boot_end_time) / 1000.0f);

    // NVS init
    esp_err_t ret = nvs_util_init();
    ESP_ERROR_CHECK(ret);

    // WiFi
    ESP_LOGI(TAG, "Connecting to WiFi...");
    wifi_init_sta();

    // NTP
    ESP_LOGI(TAG, "Initializing NTP...");
    initialize_sntp();

    // MQTT
    ESP_LOGI(TAG, "Starting MQTT...");
    mqtt_app_start();

    // Sensor Task
    ESP_LOGI(TAG, "Starting Sensor Task...");
    xTaskCreate(sensor_task, "sensor_task", 4096, NULL, 5, NULL);

    // OTA Task
    ESP_LOGI(TAG, "Starting OTA Task...");
    xTaskCreate(ota_task, "ota_task", 16384, NULL, 5, NULL);

    ESP_LOGI(TAG, "System initialized. Waiting for MQTT OTA trigger...");

    // run ecdsa verify P-256
    // run_ecdsa_verify_p256();

    // // run ecdsa verify P-384
    // run_ecdsa_verify_p384();

    // run ecdsa verify P-256 ESP32 optimized
    // run_ecdsa_verify_p256_esp32();
}