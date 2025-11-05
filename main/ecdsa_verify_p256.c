#include "mbedtls/pk.h"
#include "mbedtls/sha256.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "ecdsa_verify_p256.h"

static const char *pubkey_pem =
    "-----BEGIN PUBLIC KEY-----\n"
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEZ6wyNNruJ9hi9HWpUaEsp9QjgTST\n"
    "wBvoYjePyNgQvCO8P6+YjLRgWnFCc3cT11KUuhzmgvCmIIo/O8HFcnqTaw==\n"
    "-----END PUBLIC KEY-----\n";

static const char *message = "Hello ESP32";

// Signature hex string hasil dari Python
static const char *signature_hex =
    "3046022100a9346619cc786fec8ab332aa2c98a233a71672d7c8aaa3439e3cd7da767fec17022100fb4f8f3cf682adc482f88429156822fefcfe74c40258db8e34f2e7e35b3c5c8c";

/**
 * Convert hex string → bytes (uint8_t array)
 */
static size_t hex_to_bytes(const char *hex, uint8_t *out)
{
    size_t len = strlen(hex);
    size_t out_len = 0;

    for (size_t i = 0; i < len; i += 2)
    {
        if (!isxdigit((unsigned char)hex[i]) || !isxdigit((unsigned char)hex[i + 1]))
        {
            break;
        }
        unsigned int byte;
        sscanf(&hex[i], "%2x", &byte);
        out[out_len++] = (uint8_t)byte;
    }

    return out_len;
}

/**
 * Task untuk verify signature sekali jalan
 */
void ecdsa_verify_task(void *arg)
{
    int ret;
    uint8_t hash[32];
    uint8_t sig_bytes[128];
    mbedtls_pk_context pk;

    mbedtls_pk_init(&pk);

    // Konversi signature hex ke bytes
    size_t sig_len = hex_to_bytes(signature_hex, sig_bytes);
    if (sig_len == 0)
    {
        printf("Failed convert signature hex to bytes\n");
        vTaskDelete(NULL);
        return;
    }

    // Parse public key PEM
    ret = mbedtls_pk_parse_public_key(&pk,
                                      (const unsigned char *)pubkey_pem,
                                      strlen(pubkey_pem) + 1);
    if (ret != 0)
    {
        printf("Failed parse public key: -0x%04X\n", -ret);
        vTaskDelete(NULL);
        return;
    }

    // Hash message
    mbedtls_sha256((const unsigned char *)message, strlen(message), hash, 0);

    // Verify signature (DER)
    ret = mbedtls_pk_verify(&pk, MBEDTLS_MD_SHA256, hash, 0,
                            sig_bytes, sig_len);

    mbedtls_pk_free(&pk);

    if (ret == 0)
    {
        printf("ECDSA P-256 signature verification SUCCESS\n");
    }
    else
    {
        printf("ECDSA P-384 signature verification FAILED: -0x%04X\n", -ret);
    }

    vTaskDelete(NULL); // hapus task setelah selesai
}

/**
 * Fungsi helper untuk panggil task dari main
 */
void run_ecdsa_verify_p256(void)
{
    xTaskCreate(ecdsa_verify_task, "ecdsa_verify_task", 4096, NULL, 5, NULL);
}