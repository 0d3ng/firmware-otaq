#include <stdio.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "mqtt_app.h"
#include <stdlib.h>
#include <time.h>

static const char *TAG = "sensor_task";

void sensor_task(void *pvParameter)
{
    while (1)
    {
        int dummy_value = rand() % 100; // dummy sensor
        char payload[32];
        snprintf(payload, sizeof(payload), "{\"sensor\":%d}", dummy_value);
        mqtt_publish("device/002/sensor", payload);

        time_t now;
        struct tm timeinfo;
        time(&now);
        localtime_r(&now, &timeinfo); // Pastikan timezone sudah JST
        ESP_LOGI(TAG, "[%04d-%02d-%02d %02d:%02d:%02d] Published sensor value: %d",
                 timeinfo.tm_year + 1900,
                 timeinfo.tm_mon + 1,
                 timeinfo.tm_mday,
                 timeinfo.tm_hour,
                 timeinfo.tm_min,
                 timeinfo.tm_sec,
                 dummy_value);

        vTaskDelay(pdMS_TO_TICKS(5000));
    }
}