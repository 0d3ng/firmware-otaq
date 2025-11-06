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
#include <time.h>

static const char *TAG = "main_app";

void app_main(void)
{
    printf("Running firmware version: %s\n", FIRMWARE_VERSION);
    ESP_LOGI(TAG, "Starting system...");

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
    time_t now, ota_start_time = 0;
    struct tm timeinfo;
    time(&now);
    localtime_r(&now, &timeinfo);

    // create timestamp ISO 8601
    char timestamp[64];
    snprintf(timestamp, sizeof(timestamp), "%04d-%02d-%02dT%02d:%02d:%02d",
             timeinfo.tm_year + 1900, timeinfo.tm_mon + 1, timeinfo.tm_mday,
             timeinfo.tm_hour, timeinfo.tm_min, timeinfo.tm_sec);
    ESP_LOGI(TAG, "[%s] System time checked", timestamp);
    if (now < 1700000000)
    {
        ESP_LOGW(TAG, "System time not set. Waiting for NTP sync...");
        return;
    }

    if (nvs_util_get_u64("ota", "download_time", (uint64_t *)&ota_start_time) == ESP_OK)
    {
        time_t delta = now - ota_start_time;
        double delta_ms = (double)delta * 1000.0;
        ESP_LOGI(TAG, "App ready: %.2f ms (%.2f s)", delta_ms, (double)delta);
        nvs_util_erase_key("ota", "download_time");
    }

    // run ecdsa verify P-256
    // run_ecdsa_verify_p256();

    // // run ecdsa verify P-384
    // run_ecdsa_verify_p384();

    // run ecdsa verify P-256 ESP32 optimized
    // run_ecdsa_verify_p256_esp32();
}