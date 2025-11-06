#include "mbedtls/pk.h"
#include "mbedtls/sha512.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "ecdsa_verify_p384.h"

// Public key P-384 PEM
static const char *pubkey_pem =
    "-----BEGIN PUBLIC KEY-----\n"
    "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEwM0/3EjLm4NWw93US1b0fKsaKCU+V0Wm\n"
    "kZGjXEzA/Or8vULjR3a0qGSduQiOkxZPK9PTtbEYOd68pNncU+hekK6RExZ7WwlK\n"
    "Dfr892bIWC4JnuiytMRzgnQIeFiaF7ZZ\n"
    "-----END PUBLIC KEY-----\n";

// Pesan yang di-hash
static const char *message = "Hello ESP32";

// Signature hex dari Python ECDSA P-384 (DER)
static const char *signature_hex =
    "306402306e1ef6cee4d0783708f1acb11bc78b62b8895a793df13072a6221794594938599ad9fe98f503f6e248d325591d474f3b023004b9a09d397c15fb9169dd89c1a619a14b0669469db4d014b647d63c3662cf19c9ef44b3c257d0b65e2afac4c50fb199";

// -------------------------------------------------------------------
// Convert hex string → bytes
static size_t hex_to_bytes(const char *hex, uint8_t *out)
{
    size_t len = strlen(hex);
    size_t out_len = 0;

    for (size_t i = 0; i < len; i += 2)
    {
        if (!isxdigit((unsigned char)hex[i]) || !isxdigit((unsigned char)hex[i + 1]))
            break;

        unsigned int byte;
        sscanf(&hex[i], "%2x", &byte);
        out[out_len++] = (uint8_t)byte;
    }

    return out_len;
}

// -------------------------------------------------------------------
// Task untuk verify signature sekali jalan
void ecdsa_verify_p384_task(void *arg)
{
    int ret;
    uint8_t hash[48];       // SHA-384
    uint8_t sig_bytes[192]; // cukup besar untuk P-384 signature
    mbedtls_pk_context pk;

    mbedtls_pk_init(&pk);

    // Konversi signature
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

    // Hash message dengan SHA-384
    mbedtls_sha512((const unsigned char *)message, strlen(message), hash, 1); // 1 → SHA-384

    // Verify signature
    ret = mbedtls_pk_verify(&pk, MBEDTLS_MD_SHA384, hash, 0,
                            sig_bytes, sig_len);

    mbedtls_pk_free(&pk);

    if (ret == 0)
        printf("ECDSA P-384 signature verification SUCCESS\n");
    else
        printf("ECDSA P-384 signature verification FAILED: -0x%04X\n", -ret);

    vTaskDelete(NULL);
}

// -------------------------------------------------------------------
// Helper untuk panggil task dari main
void run_ecdsa_verify_p384(void)
{
    xTaskCreate(ecdsa_verify_p384_task, "ecdsa_verify_p384_task", 4096, NULL, 5, NULL);
}