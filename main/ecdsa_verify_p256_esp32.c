#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "mbedtls/pk.h"
#include "mbedtls/sha256.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/error.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "ecdsa_verify_p256_esp32.h"

static const char *TAG = "ECDSA_VERIFY";

// Public key PEM (SECP256R1)
// static const char *pubkey_pem =
//     "-----BEGIN PUBLIC KEY-----\n"
//     "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEZ6wyNNruJ9hi9HWpUaEsp9QjgTST\n"
//     "wBvoYjePyNgQvCO8P6+YjLRgWnFCc3cT11KUuhzmgvCmIIo/O8HFcnqTaw==\n"
//     "-----END PUBLIC KEY-----\n";

// Signature hex (ASN.1 DER)
static const char *signature_hex =
    "3045022100ac64e77f131921e436dd6b6337f82cdd8e6bdf930256230a6d5723767c3ecff002207f3c9a44c14bba2d3e6c406056447c3227b97cb15522423e80dccd20e3c7fab7";

// SHA256 hash hex
static const char *hash_hex =
    "4c255e8dbd13c1e784346aa0020143e67e596b72ed5534cd22886b8709692864";

// Convert hex string to bytes
static int hexstr_to_bytes(const char *hex, uint8_t *out, size_t max_len)
{
    size_t len = strlen(hex);
    if (len % 2 != 0 || max_len < len / 2)
        return -1;

    for (size_t i = 0; i < len / 2; ++i)
    {
        unsigned int byte;
        if (sscanf(hex + i * 2, "%2x", &byte) != 1)
            return -2;
        out[i] = (uint8_t)byte;
    }
    return len / 2;
}

// void verify_signature_task(void *arg)
// {
//     mbedtls_pk_context pk;
//     uint8_t hash[32];
//     uint8_t signature[128];

//     mbedtls_pk_init(&pk);

//     // Parse public key
//     int ret = mbedtls_pk_parse_public_key(&pk,
//                                           (const unsigned char *)pubkey_pem,
//                                           strlen(pubkey_pem) + 1);
//     if (ret != 0)
//     {
//         ESP_LOGE(TAG, "Failed to parse public key: -0x%04X", -ret);
//         vTaskDelete(NULL);
//         return;
//     }

//     // Convert hash hex to bytes
//     ret = hexstr_to_bytes(hash_hex, hash, sizeof(hash));
//     if (ret != 32)
//     {
//         ESP_LOGE(TAG, "Invalid hash length: %d", ret);
//         vTaskDelete(NULL);
//         return;
//     }

//     // Convert signature hex to bytes
//     int sig_len = hexstr_to_bytes(signature_hex, signature, sizeof(signature));
//     if (sig_len <= 0)
//     {
//         ESP_LOGE(TAG, "Invalid signature hex");
//         vTaskDelete(NULL);
//         return;
//     }

//     ESP_LOGI(TAG, "sig_len=%d", sig_len);
//     ESP_LOG_BUFFER_HEX(TAG, hash, 32);
//     ESP_LOG_BUFFER_HEX(TAG, signature, sig_len);

//     // Verify signature
//     ret = mbedtls_pk_verify(&pk, MBEDTLS_MD_SHA256, hash, 0, signature, sig_len);
//     if (ret == 0)
//     {
//         ESP_LOGI(TAG, "Signature verification SUCCESS");
//     }
//     else
//     {
//         char err_buf[128];
//         mbedtls_strerror(ret, err_buf, sizeof(err_buf));
//         ESP_LOGE(TAG, "Signature verification FAILED: -0x%04X (%s)", -ret, err_buf);
//     }
//     mbedtls_pk_free(&pk);
//     vTaskDelete(NULL);
// }

void verify_signature_task(void *arg)
{
    const char *pubkey_pem =
        "-----BEGIN PUBLIC KEY-----\n"
        "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEZ6wyNNruJ9hi9HWpUaEsp9QjgTST\n"
        "wBvoYjePyNgQvCO8P6+YjLRgWnFCc3cT11KUuhzmgvCmIIo/O8HFcnqTaw==\n"
        "-----END PUBLIC KEY-----\n";

    uint8_t hash[32] = {
        0x4c, 0x25, 0x5e, 0x8d, 0xbd, 0x13, 0xc1, 0xe7,
        0x84, 0x34, 0x6a, 0xa0, 0x02, 0x01, 0x43, 0xe6,
        0x7e, 0x59, 0x6b, 0x72, 0xed, 0x55, 0x34, 0xcd,
        0x22, 0x88, 0x6b, 0x87, 0x09, 0x69, 0x28, 0x64};

    uint8_t signature[] = {
        0x30, 0x45, 0x02, 0x21, 0x00, 0xac, 0x64, 0xe7, 0x7f, 0x13, 0x19, 0x21, 0xe4,
        0x36, 0xdd, 0x6b, 0x63, 0x37, 0xf8, 0x2c, 0xdd, 0x8e, 0x6b, 0xdf, 0x93, 0x02,
        0x56, 0x23, 0x0a, 0x6d, 0x57, 0x23, 0x76, 0x7c, 0x3e, 0xcf, 0xf0, 0x02, 0x20,
        0x7f, 0x3c, 0x9a, 0x44, 0xc1, 0x4b, 0xba, 0x2d, 0x3e, 0x6c, 0x40, 0x60, 0x56,
        0x44, 0x7c, 0x32, 0x27, 0xb9, 0x7c, 0xb1, 0x55, 0x22, 0x42, 0x3e, 0x80, 0xdc,
        0xcd, 0x20, 0xe3, 0xc7, 0xfa, 0xb7};

    mbedtls_pk_context pk;
    mbedtls_pk_init(&pk);

    int ret = mbedtls_pk_parse_public_key(&pk, (const unsigned char *)pubkey_pem, strlen(pubkey_pem) + 1);
    if (ret != 0)
    {
        ESP_LOGE(TAG, "Failed to parse public key: -0x%04x", -ret);
        vTaskDelete(NULL);
        return;
    }

    // Verifikasi signature
    ret = mbedtls_pk_verify(&pk, MBEDTLS_MD_SHA256, hash, sizeof(hash), signature, sizeof(signature));
    if (ret == 0)
    {
        ESP_LOGI(TAG, "✅ Signature verified successfully!");
    }
    else
    {
        ESP_LOGE(TAG, "❌ Signature verification FAILED: -0x%04x", -ret);
        vTaskDelete(NULL);
        return;
    }

    mbedtls_pk_free(&pk);
    vTaskDelete(NULL);
}

void run_ecdsa_verify_p256_esp32(void)
{
    xTaskCreate(verify_signature_task, "verify_signature_task", 4096, NULL, 5, NULL);
}