#include "ota_updater.h"
#include "esp_log.h"
#include "esp_https_ota.h"
#include "esp_ota_ops.h"
#include "esp_http_client.h"
#include "esp_system.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "monocypher-ed25519.h"
#include "mbedtls/sha256.h"
#include "../miniz/miniz.h"
#include "cJSON.h"
#include <string.h>
#include <stdlib.h>

#define OTA_URL "https://yourserver.com/firmware_package.zip"
#define TAG "OTA_SECURE"
#define MAX_SIZE (1024 * 512)
#define SIG_LEN 64

static const uint8_t PUBLIC_KEY[32] = {/* isi public key kamu */};
static volatile bool ota_flag = false;

void ota_trigger() { ota_flag = true; }
bool ota_triggered(void)
{
    if (ota_flag)
    {
        ota_flag = false;
        return true;
    }
    return false;
}

static uint8_t *download_zip(const char *url, size_t *out_len)
{
    esp_http_client_config_t config = {.url = url, .timeout_ms = 15000};
    esp_http_client_handle_t client = esp_http_client_init(&config);
    if (!client)
        return NULL;

    if (esp_http_client_open(client, 0) != ESP_OK)
    {
        esp_http_client_cleanup(client);
        return NULL;
    }

    int content_len = esp_http_client_fetch_headers(client);
    if (content_len <= 0)
    {
        esp_http_client_cleanup(client);
        return NULL;
    }

    uint8_t *buffer = malloc(content_len);
    if (!buffer)
    {
        esp_http_client_cleanup(client);
        return NULL;
    }

    int read_len = esp_http_client_read_response(client, (char *)buffer, content_len);
    esp_http_client_cleanup(client);
    if (read_len != content_len)
    {
        free(buffer);
        return NULL;
    }

    *out_len = content_len;
    return buffer;
}

static bool verify_hash(const char *manifest_str, const uint8_t *firmware, size_t fw_len)
{
    cJSON *json = cJSON_Parse(manifest_str);
    if (!json)
        return false;

    const cJSON *hash = cJSON_GetObjectItem(json, "hash");
    if (!hash)
    {
        cJSON_Delete(json);
        return false;
    }

    uint8_t sha256[32];
    mbedtls_sha256_context ctx;
    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts(&ctx, 0);
    mbedtls_sha256_update(&ctx, firmware, fw_len);
    mbedtls_sha256_finish(&ctx, sha256);
    mbedtls_sha256_free(&ctx);

    char hash_hex[65];
    for (int i = 0; i < 32; i++)
        sprintf(hash_hex + i * 2, "%02x", sha256[i]);
    hash_hex[64] = '\0';

    bool match = strcmp(hash_hex, hash->valuestring) == 0;
    cJSON_Delete(json);
    return match;
}

static bool verify_signature(const uint8_t *manifest, size_t manifest_len, const uint8_t *signature)
{
    return crypto_ed25519_check(signature, PUBLIC_KEY, manifest, manifest_len) == 0;
}

bool extract_file_from_zip(const void *zip_data, size_t zip_size, const char *filename, uint8_t *out_buf, size_t max_len, size_t *out_len)
{
    mz_zip_archive zip;
    memset(&zip, 0, sizeof(zip));

    if (!mz_zip_reader_init_mem(&zip, zip_data, zip_size, 0))
    {
        ESP_LOGE(TAG, "ZIP init failed");
        return false;
    }

    int file_index = mz_zip_reader_locate_file(&zip, filename, NULL, 0);
    if (file_index < 0)
    {
        ESP_LOGE(TAG, "File %s not found in ZIP", filename);
        mz_zip_reader_end(&zip);
        return false;
    }

    mz_zip_archive_file_stat file_stat;
    if (!mz_zip_reader_file_stat(&zip, file_index, &file_stat))
    {
        ESP_LOGE(TAG, "Failed to stat file %s", filename);
        mz_zip_reader_end(&zip);
        return false;
    }

    if (file_stat.m_uncomp_size > max_len)
    {
        ESP_LOGE(TAG, "File %s too large", filename);
        mz_zip_reader_end(&zip);
        return false;
    }

    if (!mz_zip_reader_extract_to_mem(&zip, file_index, out_buf, max_len, 0))
    {
        ESP_LOGE(TAG, "Failed to extract %s", filename);
        mz_zip_reader_end(&zip);
        return false;
    }

    *out_len = file_stat.m_uncomp_size;
    mz_zip_reader_end(&zip);
    return true;
}

void ota_task(void *pvParameter)
{
    uint8_t buffer[MAX_SIZE];

    while (1)
    {
        if (!ota_triggered())
        {
            vTaskDelay(pdMS_TO_TICKS(1000));
            continue;
        }

        ESP_LOGI(TAG, "Downloading OTA package...");
        size_t zip_len;
        uint8_t *zip_data = download_zip(OTA_URL, &zip_len);
        if (!zip_data)
            continue;

        size_t manifest_len;
        if (!extract_file_from_zip(zip_data, zip_len, "manifest.json", buffer, MAX_SIZE, &manifest_len))
        {
            free(zip_data);
            continue;
        }

        char *manifest = malloc(manifest_len + 1);
        if (!manifest)
        {
            free(zip_data);
            continue;
        }
        memcpy(manifest, buffer, manifest_len);
        manifest[manifest_len] = '\0';

        size_t fw_len;
        if (!extract_file_from_zip(zip_data, zip_len, "firmware.bin", buffer, MAX_SIZE, &fw_len))
        {
            free(manifest);
            free(zip_data);
            continue;
        }

        uint8_t *firmware = malloc(fw_len);
        if (!firmware)
        {
            free(manifest);
            free(zip_data);
            continue;
        }
        memcpy(firmware, buffer, fw_len);

        size_t sig_len;
        if (!extract_file_from_zip(zip_data, zip_len, "firmware.sig", buffer, MAX_SIZE, &sig_len) || sig_len != SIG_LEN)
        {
            free(firmware);
            free(manifest);
            free(zip_data);
            continue;
        }

        uint8_t *signature = malloc(sig_len);
        if (!signature)
        {
            free(firmware);
            free(manifest);
            free(zip_data);
            continue;
        }
        memcpy(signature, buffer, sig_len);
        free(zip_data);

        if (!verify_hash(manifest, firmware, fw_len))
        {
            ESP_LOGE(TAG, "Hash mismatch");
            goto cleanup;
        }

        if (!verify_signature(firmware, fw_len, signature))
        {
            ESP_LOGE(TAG, "Signature invalid");
            goto cleanup;
        }

        ESP_LOGI(TAG, "Firmware verified. Starting OTA...");

        const esp_partition_t *update_partition = esp_ota_get_next_update_partition(NULL);
        esp_ota_handle_t ota_handle;
        if (esp_ota_begin(update_partition, fw_len, &ota_handle) != ESP_OK ||
            esp_ota_write(ota_handle, firmware, fw_len) != ESP_OK ||
            esp_ota_end(ota_handle) != ESP_OK ||
            esp_ota_set_boot_partition(update_partition) != ESP_OK)
        {
            ESP_LOGE(TAG, "OTA failed");
            goto cleanup;
        }

        ESP_LOGI(TAG, "OTA success. Rebooting...");
        vTaskDelay(pdMS_TO_TICKS(500));
        esp_restart();

    cleanup:
        free(signature);
        free(firmware);
        free(manifest);
    }
}