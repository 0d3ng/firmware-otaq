#include <stdio.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "mqtt_app.h"
#include <stdlib.h>
#include <time.h>
#include "DHT22.h"

#define PIN_GPIO_DHT22 4
static const char *TAG = "sensor_task";

void sensor_task(void *pvParameter)
{
    uint16_t temperature, humidity;
    DHTinit(PIN_GPIO_DHT22);
    vTaskDelay(pdMS_TO_TICKS(1000)); // Tunggu sensor siap
    ESP_LOGI(TAG, "Sensor DHT22 ready. Starting data read loop...");
    while (1)
    {
        TickType_t T0 = xTaskGetTickCount();
        // Second driver call
        int r = DHTget(&temperature, &humidity);
        TickType_t T1 = xTaskGetTickCount();
        if (r < 0)
        {
            ESP_LOGE(TAG, "DHT22 read error: %d", r);
        }
        else
        {
            float temperature_c = temperature / 10.0;
            float humidity_rh = humidity / 10.0;
            ESP_LOGI(TAG, "DHT22 read success: Temp=%.2f°C, Humi=%.2f%% (Time taken: %d ticks)", temperature_c, humidity_rh, (T1 - T0) * portTICK_PERIOD_MS);
            // Buat payload JSON
            char payload[128];
            snprintf(payload, sizeof(payload),
                     "{\"temperature\":%.2f,\"humidity\":%.2f}",
                     temperature_c, humidity_rh);

            // Publish ke MQTT
            mqtt_publish("device/002/sensor", payload);

            // Waktu sekarang
            time_t now;
            struct tm timeinfo;
            time(&now);
            localtime_r(&now, &timeinfo);

            ESP_LOGI(TAG, "[%04d-%02d-%02d %02d:%02d:%02d] Published Temp: %.2f°C | Humi: %.2f%%",
                     timeinfo.tm_year + 1900,
                     timeinfo.tm_mon + 1,
                     timeinfo.tm_mday,
                     timeinfo.tm_hour,
                     timeinfo.tm_min,
                     timeinfo.tm_sec,
                     temperature_c,
                     humidity_rh);
        }
        vTaskDelay(pdMS_TO_TICKS(5000));
    }
}