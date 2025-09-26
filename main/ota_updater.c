#include "ota_updater.h"
#include "esp_log.h"
#include "esp_https_ota.h"
#include "esp_ota_ops.h"
#include "esp_task_wdt.h"
#include "esp_http_client.h"
#include "esp_system.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "monocypher-ed25519.h"
#include "mbedtls/sha256.h"
#include "../miniz/miniz.h"
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>

// production
// #define OTA_URL "https://fastapi.sinaungoding.com/api/v1/firmware/firmware.zip"
// development
#define OTA_URL "http://192.168.10.102:8000/api/v1/firmware/firmware.zip"
#define TAG "OTA_SECURE"
#define MAX_SIZE 8192
#define SIG_LEN 64

static const uint8_t PUBLIC_KEY[32] = {0x23, 0x1F, 0x48, 0x12, 0x84, 0xAF, 0x53, 0x40, 0xF5, 0xCC, 0x36, 0xBD, 0x27, 0xA8, 0x84, 0x25, 0x14, 0x88, 0xD1, 0xD0, 0x41, 0x38, 0xDE, 0x9D, 0x45, 0x6C, 0xF2, 0x6D, 0x28, 0xD9, 0xF9, 0xEF};
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
    esp_http_client_config_t config = {
        .url = url,
        .cert_pem = NULL, // Add server certificate if needed
        .skip_cert_common_name_check = true,
        .timeout_ms = 15000};
    esp_http_client_handle_t client = esp_http_client_init(&config);
    if (!client)
    {
        ESP_LOGE(TAG, "Failed to init HTTP client");
        return NULL;
    }
    esp_err_t err = esp_http_client_open(client, 0);
    if (err != ESP_OK)
    {
        ESP_LOGE(TAG, "esp_http_client_open failed: %s", esp_err_to_name(err));
        esp_http_client_cleanup(client);
        return NULL;
    }

    int content_len = esp_http_client_fetch_headers(client);
    if (content_len <= 0)
    {
        ESP_LOGE(TAG, "Invalid content length: %d", content_len);
        esp_http_client_cleanup(client);
        return NULL;
    }
    ESP_LOGI(TAG, "Content length: %d", content_len);
    uint8_t *buffer = malloc(content_len);
    if (!buffer)
    {
        ESP_LOGE(TAG, "Failed to malloc %d bytes", content_len);
        esp_http_client_cleanup(client);
        return NULL;
    }

    int read_len = esp_http_client_read_response(client, (char *)buffer, content_len);
    esp_http_client_cleanup(client);
    if (read_len != content_len)
    {
        ESP_LOGE(TAG, "esp_http_client_read_response failed: %d", read_len);
        free(buffer);
        return NULL;
    }

    *out_len = content_len;
    return buffer;
}

static bool parse_manifest(const char *manifest_str, char *hash_out, size_t hash_len, char *sig_out, size_t sig_len)
{
    const char *hash_key = "\"hash\":\"";
    const char *sig_key = "\"signature\":\"";

    char *start = strstr(manifest_str, hash_key);
    if (!start)
        return false;
    start += strlen(hash_key);
    char *end = strchr(start, '"');
    if (!end || (end - start >= hash_len))
        return false;
    memcpy(hash_out, start, end - start);
    hash_out[end - start] = '\0';

    start = strstr(manifest_str, sig_key);
    if (!start)
        return false;
    start += strlen(sig_key);
    end = strchr(start, '"');
    if (!end || (end - start >= sig_len))
        return false;
    memcpy(sig_out, start, end - start);
    sig_out[end - start] = '\0';

    return true;
}

// Verify firmware hash
static bool verify_hash(const uint8_t *firmware, size_t fw_len, const char *expected_hash)
{
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

    return strcmp(hash_hex, expected_hash) == 0;
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
    while (1)
    {
        if (!ota_triggered())
        {
            vTaskDelay(pdMS_TO_TICKS(1000));
            continue;
        }

        ESP_LOGI(TAG, "[OTA] Triggered");

        // 1. Download ZIP
        size_t zip_len;
        ESP_LOGI(TAG, "[OTA] Downloading ZIP from %s...", OTA_URL);
        uint8_t *zip_data = download_zip(OTA_URL, &zip_len);
        if (!zip_data)
        {
            ESP_LOGE(TAG, "[OTA] Download failed");
            continue;
        }

        // 2. Buffer ekstrak sementara
        uint8_t *buffer = malloc(MAX_SIZE);
        if (!buffer)
        {
            ESP_LOGE(TAG, "[OTA] Buffer malloc failed");
            free(zip_data);
            continue;
        }

        // 3. Extract manifest.json
        size_t manifest_len;
        ESP_LOGI(TAG, "[OTA] Extracting manifest...");
        if (!extract_file_from_zip(zip_data, zip_len, "manifest.json", buffer, MAX_SIZE, &manifest_len))
        {
            ESP_LOGE(TAG, "[OTA] Extract manifest failed");
            free(buffer);
            free(zip_data);
            continue;
        }

        char *manifest = malloc(manifest_len + 1);
        if (!manifest)
        {
            ESP_LOGE(TAG, "[OTA] Manifest malloc failed");
            free(buffer);
            free(zip_data);
            continue;
        }
        memcpy(manifest, buffer, manifest_len);
        manifest[manifest_len] = '\0';
        ESP_LOGI(TAG, "[OTA] Manifest extracted:\n%s", manifest);

        // 4. Extract firmware-otaq.bin
        size_t fw_len;
        ESP_LOGI(TAG, "[OTA] Extracting firmware...");
        if (!extract_file_from_zip(zip_data, zip_len, "firmware-otaq.bin", buffer, MAX_SIZE, &fw_len))
        {
            ESP_LOGE(TAG, "[OTA] Extract firmware failed");
            free(manifest);
            free(buffer);
            free(zip_data);
            continue;
        }

        uint8_t *firmware = malloc(fw_len);
        if (!firmware)
        {
            ESP_LOGE(TAG, "[OTA] Firmware malloc failed");
            free(manifest);
            free(buffer);
            free(zip_data);
            continue;
        }
        memcpy(firmware, buffer, fw_len);
        free(buffer);
        free(zip_data);

        // 5. Parse manifest -> hash & signature
        char expected_hash[65];
        char signature_hex[128];
        if (!parse_manifest(manifest, expected_hash, sizeof(expected_hash), signature_hex, sizeof(signature_hex)))
        {
            ESP_LOGE(TAG, "[OTA] Parse manifest failed");
            goto cleanup;
        }
        ESP_LOGI(TAG, "[OTA] Expected hash: %s", expected_hash);
        ESP_LOGI(TAG, "[OTA] Expected signature: %s", signature_hex);

        uint8_t signature[64];
        for (int i = 0; i < 64; i++)
            sscanf(signature_hex + i * 2, "%2hhx", &signature[i]);
        ESP_LOGI(TAG, "[OTA] Signature converted to bytes");

        if (!verify_hash(firmware, fw_len, expected_hash))
        {
            ESP_LOGE(TAG, "[OTA] Hash mismatch");
            goto cleanup;
        }
        if (!verify_signature(firmware, fw_len, signature))
        {
            ESP_LOGE(TAG, "[OTA] Signature invalid");
            goto cleanup;
        }

        ESP_LOGI(TAG, "[OTA] Firmware verified. Starting OTA...");
        const esp_partition_t *update_partition = esp_ota_get_next_update_partition(NULL);
        esp_ota_handle_t ota_handle;

        if (esp_ota_begin(update_partition, OTA_SIZE_UNKNOWN, &ota_handle) != ESP_OK)
        {
            ESP_LOGE(TAG, "[OTA] OTA begin failed");
            goto cleanup;
        }

        // 6. Write firmware per chunk + reset WDT
        size_t chunk_size = 1024;
        for (size_t offset = 0; offset < fw_len; offset += chunk_size)
        {
            size_t write_size = (offset + chunk_size > fw_len) ? (fw_len - offset) : chunk_size;
            esp_err_t err = esp_ota_write(ota_handle, firmware + offset, write_size);
            if (err != ESP_OK)
            {
                ESP_LOGE(TAG, "[OTA] OTA write failed at offset %d", offset);
                esp_ota_end(ota_handle);
                goto cleanup;
            }
            esp_task_wdt_reset(); // reset WDT
            int progress = (int)(((offset + write_size) * 100) / fw_len);
            ESP_LOGI(TAG, "[OTA] Progress: %d%% (%d/%d bytes)", progress, offset + write_size, fw_len);
        }

        if (esp_ota_end(ota_handle) != ESP_OK || esp_ota_set_boot_partition(update_partition) != ESP_OK)
        {
            ESP_LOGE(TAG, "[OTA] OTA end/set boot failed");
            goto cleanup;
        }

        ESP_LOGI(TAG, "[OTA] OTA success. Rebooting...");
        vTaskDelay(pdMS_TO_TICKS(500));
        esp_restart();

    cleanup:
        free(firmware);
        free(manifest);
    }
}