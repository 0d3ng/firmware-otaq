#include "ota_updater.h"
#include "esp_log.h"
#include "esp_system.h"
#include "esp_ota_ops.h"
#include "esp_http_client.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "monocypher.h"
#include "unzip.h"
#include "cJSON.h"
#include <string.h>
#include <stdlib.h>

static const char *TAG = "ota_updater";

#define OTA_ZIP_URL "https://yourserver.example.com/update_package.zip"
#define BUFFER_SIZE 1024
#define SIG_LEN 64
#define MAX_FILE_SIZE (1024 * 512) // 512 KB untuk buffer ekstraksi

// Replace dengan public key kamu
static const uint8_t PUBLIC_KEY[32] = {/* fill public key bytes */};

// Flag OTA trigger via MQTT
static volatile bool ota_flag = false;

void ota_trigger()
{
    ota_flag = true;
}

bool ota_triggered()
{
    if (ota_flag)
    {
        ota_flag = false;
        return true;
    }
    return false;
}

// Download file dari URL ke memory
static uint8_t *download_file(const char *url, size_t *out_len)
{
    esp_http_client_config_t config = {
        .url = url,
        .timeout_ms = 15000,
    };
    esp_http_client_handle_t client = esp_http_client_init(&config);
    if (!client)
        return NULL;

    if (esp_http_client_open(client, 0) != ESP_OK)
    {
        ESP_LOGE(TAG, "Failed to open URL");
        esp_http_client_cleanup(client);
        return NULL;
    }

    int content_len = esp_http_client_fetch_headers(client);
    if (content_len <= 0)
    {
        ESP_LOGE(TAG, "Invalid content length");
        esp_http_client_cleanup(client);
        return NULL;
    }

    uint8_t *buffer = malloc(content_len);
    if (!buffer)
    {
        esp_http_client_cleanup(client);
        return NULL;
    }

    int read_len = esp_http_client_read(client, (char *)buffer, content_len);
    if (read_len != content_len)
    {
        ESP_LOGE(TAG, "Read mismatch");
        free(buffer);
        esp_http_client_cleanup(client);
        return NULL;
    }

    *out_len = content_len;
    esp_http_client_cleanup(client);
    return buffer;
}

// Verifikasi Ed25519 signature
static bool verify_signature(const uint8_t *firmware, size_t fw_len, const uint8_t *sig)
{
    uint8_t hash[64];
    crypto_sha512(hash, firmware, fw_len);
    return crypto_sign_check(sig, hash, sizeof(hash), PUBLIC_KEY) == 0;
}

// Parse manifest.json dan cek hash firmware
static bool parse_manifest(const char *manifest_str, const uint8_t *firmware, size_t fw_len)
{
    cJSON *json = cJSON_Parse(manifest_str);
    if (!json)
        return false;

    const cJSON *version = cJSON_GetObjectItem(json, "version");
    const cJSON *hash = cJSON_GetObjectItem(json, "hash");
    if (!version || !hash)
    {
        cJSON_Delete(json);
        return false;
    }

    uint8_t fw_sha256[32];
    crypto_sha256(fw_sha256, firmware, fw_len);

    char fw_hash_hex[65];
    for (int i = 0; i < 32; i++)
        sprintf(fw_hash_hex + i * 2, "%02x", fw_sha256[i]);
    fw_hash_hex[64] = '\0';

    bool ok = strcmp(fw_hash_hex, hash->valuestring) == 0;
    cJSON_Delete(json);
    return ok;
}

void ota_task(void *pvParameter)
{
    uint8_t file_buffer[MAX_FILE_SIZE];

    while (1)
    {
        if (!ota_triggered())
        {
            vTaskDelay(pdMS_TO_TICKS(1000));
            continue;
        }

        ESP_LOGI(TAG, "OTA triggered! Downloading update package...");

        size_t zip_len;
        uint8_t *zip_data = download_file(OTA_ZIP_URL, &zip_len);
        if (!zip_data)
        {
            ESP_LOGE(TAG, "Failed to download update package");
            continue;
        }

        UNZIP_FILE zip_file;
        if (unzip_open_from_memory(zip_data, zip_len, &zip_file) != UNZIP_OK)
        {
            ESP_LOGE(TAG, "Failed to open ZIP");
            free(zip_data);
            continue;
        }

        // Extract manifest.json
        size_t manifest_len;
        if (unzip_extract_to_buffer(&zip_file, "manifest.json", file_buffer, MAX_FILE_SIZE, &manifest_len) != UNZIP_OK)
        {
            ESP_LOGE(TAG, "manifest.json not found");
            unzip_close(&zip_file);
            free(zip_data);
            continue;
        }
        char *manifest_str = malloc(manifest_len + 1);
        memcpy(manifest_str, file_buffer, manifest_len);
        manifest_str[manifest_len] = '\0';

        // Extract firmware.bin
        size_t fw_len;
        if (unzip_extract_to_buffer(&zip_file, "firmware.bin", file_buffer, MAX_FILE_SIZE, &fw_len) != UNZIP_OK)
        {
            ESP_LOGE(TAG, "firmware.bin not found");
            free(manifest_str);
            unzip_close(&zip_file);
            free(zip_data);
            continue;
        }
        uint8_t *firmware = malloc(fw_len);
        memcpy(firmware, file_buffer, fw_len);

        // Extract firmware.sig
        size_t sig_len;
        if (unzip_extract_to_buffer(&zip_file, "firmware.sig", file_buffer, MAX_FILE_SIZE, &sig_len) != UNZIP_OK || sig_len != SIG_LEN)
        {
            ESP_LOGE(TAG, "firmware.sig missing or wrong size");
            free(firmware);
            free(manifest_str);
            unzip_close(&zip_file);
            free(zip_data);
            continue;
        }
        uint8_t *signature = malloc(sig_len);
        memcpy(signature, file_buffer, sig_len);

        unzip_close(&zip_file);
        free(zip_data);

        // Verify manifest
        if (!parse_manifest(manifest_str, firmware, fw_len))
        {
            ESP_LOGE(TAG, "Manifest verification failed");
            free(signature);
            free(firmware);
            free(manifest_str);
            continue;
        }

        // Verify signature
        if (!verify_signature(firmware, fw_len, signature))
        {
            ESP_LOGE(TAG, "Firmware signature invalid");
            free(signature);
            free(firmware);
            free(manifest_str);
            continue;
        }

        ESP_LOGI(TAG, "Firmware verified. Begin OTA...");

        const esp_partition_t *update_partition = esp_ota_get_next_update_partition(NULL);
        if (!update_partition)
        {
            ESP_LOGE(TAG, "No OTA partition available");
            free(signature);
            free(firmware);
            free(manifest_str);
            continue;
        }

        esp_ota_handle_t ota_handle;
        if (esp_ota_begin(update_partition, fw_len, &ota_handle) != ESP_OK)
        {
            ESP_LOGE(TAG, "esp_ota_begin failed");
            free(signature);
            free(firmware);
            free(manifest_str);
            continue;
        }

        if (esp_ota_write(ota_handle, firmware, fw_len) != ESP_OK)
        {
            ESP_LOGE(TAG, "esp_ota_write failed");
            esp_ota_end(ota_handle);
            free(signature);
            free(firmware);
            free(manifest_str);
            continue;
        }

        if (esp_ota_end(ota_handle) != ESP_OK)
        {
            ESP_LOGE(TAG, "esp_ota_end failed");
            free(signature);
            free(firmware);
            free(manifest_str);
            continue;
        }

        if (esp_ota_set_boot_partition(update_partition) != ESP_OK)
        {
            ESP_LOGE(TAG, "esp_ota_set_boot_partition failed");
            free(signature);
            free(firmware);
            free(manifest_str);
            continue;
        }

        ESP_LOGI(TAG, "OTA update complete! Rebooting...");

        free(signature);
        free(firmware);
        free(manifest_str);

        vTaskDelay(pdMS_TO_TICKS(500));
        esp_restart();
    }
}