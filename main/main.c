#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "nvs_flash.h"
#include "wifi_connect.h"
#include "mqtt_app.h"
#include "ota_updater.h"
#include "sensor_task.h"

static const char *TAG = "main_app";

void app_main(void)
{
    // NVS init
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND)
    {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    // WiFi
    wifi_init_sta();

    // MQTT
    mqtt_app_start();

    // Sensor Task
    xTaskCreate(sensor_task, "sensor_task", 4096, NULL, 5, NULL);

    // OTA Task
    xTaskCreate(ota_task, "ota_task", 8192, NULL, 5, NULL);

    ESP_LOGI(TAG, "System initialized. Waiting for MQTT OTA trigger...");
}