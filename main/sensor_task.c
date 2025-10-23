#include <stdio.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "mqtt_app.h"
#include <stdlib.h>
#include <time.h>
#include "DHT22.h"
#include "battery_voltage.h"
#include "ota_control.h"

#define PIN_GPIO_DHT22 4

#define ADC_CHANNEL ADC_CHANNEL_6 // GPIO34

static const char *TAG = "sensor_task";

void sensor_task(void *pvParameter)
{
    uint16_t temperature, humidity;
    DHTinit(PIN_GPIO_DHT22);
    vTaskDelay(pdMS_TO_TICKS(1000)); // Tunggu sensor siap
    ESP_LOGI(TAG, "Sensor DHT22 ready. Starting data read loop...");

    adc_oneshot_unit_handle_t adc_handle;
    adc_cali_handle_t cali_handle;

    battery_adc_init(&adc_handle, &cali_handle, ADC_CHANNEL);

    EventGroupHandle_t eg = ota_control_get_event_group();
    const EventBits_t PAUSE_BIT = (1 << 0);

    while (1)
    {
        // If OTA requested pause, wait until cleared
        if (eg)
        {
            EventBits_t bits = xEventGroupWaitBits(eg, PAUSE_BIT, pdFALSE, pdFALSE, pdMS_TO_TICKS(1000));
            if (bits & PAUSE_BIT)
            {
                // paused: block until resume
                ESP_LOGI(TAG, "Sensor task paused for OTA");
                xEventGroupWaitBits(eg, PAUSE_BIT, pdFALSE, pdFALSE, portMAX_DELAY);
                ESP_LOGI(TAG, "Sensor task resumed after OTA");
            }
        }

        // time log
        time_t now;
        struct tm timeinfo;
        time(&now);
        localtime_r(&now, &timeinfo);
        // create timestamp ISO 8601
        char timestamp[64];
        snprintf(timestamp, sizeof(timestamp), "%04d-%02d-%02dT%02d:%02d:%02d", timeinfo.tm_year + 1900, timeinfo.tm_mon + 1, timeinfo.tm_mday, timeinfo.tm_hour, timeinfo.tm_min, timeinfo.tm_sec);

        TickType_t T0 = xTaskGetTickCount();
        // Second driver call
        int r = DHTget(&temperature, &humidity);
        TickType_t T1 = xTaskGetTickCount();
        float temperature_c = 0.0;
        float humidity_rh = 0.0;
        if (r < 0)
        {
            ESP_LOGE(TAG, "DHT22 read error: %d", r);
        }
        else
        {
            temperature_c = temperature / 10.0;
            humidity_rh = humidity / 10.0;
            ESP_LOGI(TAG, "DHT22 read success: Temp=%.2f°C, Humi=%.2f%% (Time taken: %d ticks)", temperature_c, humidity_rh, (T1 - T0) * portTICK_PERIOD_MS);
        }

        // read battery voltage
        float voltage = battery_read_voltage(adc_handle, cali_handle, ADC_CHANNEL, 50);
        ESP_LOGI(TAG, "Battery voltage: %.3f V", voltage);

        // create JSON payload
        char payload[256];
        snprintf(payload, sizeof(payload), "{\"temperature\":%.2f,\"humidity\":%.2f,\"voltage\":%.3f,\"timestamp\":\"%s\"}", temperature_c, humidity_rh, voltage, timestamp);
        ESP_LOGI(TAG, "Payload: %s", payload);
        // publish via MQTT
        mqtt_publish("device/002/sensor", payload);

        ESP_LOGI(TAG, "[%s] Published Temp: %.2f°C | Humi: %.2f%% | Volt: %.3fV", timestamp, temperature_c, humidity_rh, voltage);

        vTaskDelay(pdMS_TO_TICKS(5000));
    }
}