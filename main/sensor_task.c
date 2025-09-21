#include <stdio.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "mqtt_app.h"
#include <stdlib.h>

static const char *TAG = "sensor_task";

void sensor_task(void *pvParameter)
{
    while (1)
    {
        int dummy_value = rand() % 100; // dummy sensor
        char payload[32];
        snprintf(payload, sizeof(payload), "{\"sensor\":%d}", dummy_value);
        mqtt_publish("device/001/sensor", payload);
        ESP_LOGI(TAG, "Published sensor value: %d", dummy_value);
        vTaskDelay(pdMS_TO_TICKS(5000));
    }
}