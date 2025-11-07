#ifndef NVS_UTIL_H
#define NVS_UTIL_H

#include "nvs_flash.h"
#include "nvs.h"
#include "esp_log.h"
#include <string.h>

#ifdef __cplusplus
extern "C"
{
#endif

    esp_err_t nvs_util_init(void);
    esp_err_t nvs_util_set_u64(const char *property, const char *key, uint64_t value);
    esp_err_t nvs_util_get_u64(const char *property, const char *key, uint64_t *out_value);
    esp_err_t nvs_util_set_i32(const char *property, const char *key, int32_t value);
    esp_err_t nvs_util_get_i32(const char *property, const char *key, int32_t *out_value);
    esp_err_t nvs_util_set_str(const char *property, const char *key, const char *value);
    esp_err_t nvs_util_get_str(const char *property, const char *key, char *out_value, size_t max_len);
    esp_err_t nvs_util_erase_key(const char *property, const char *key);

#ifdef __cplusplus
}
#endif

#endif // NVS_UTIL_H
       /* ---------------- NVS utility functions ---------------- */