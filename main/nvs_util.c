#include "nvs_util.h"

static const char *TAG = "NVS_UTIL";

esp_err_t nvs_util_init(void)
{
    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND)
    {
        ESP_ERROR_CHECK(nvs_flash_erase());
        err = nvs_flash_init();
    }
    ESP_LOGI(TAG, "NVS initialized");
    return err;
}

esp_err_t nvs_util_set_u64(const char *namespace, const char *key, uint64_t value)
{
    nvs_handle_t handle;
    esp_err_t err = nvs_open(namespace, NVS_READWRITE, &handle);
    if (err != ESP_OK)
        return err;

    err = nvs_set_u64(handle, key, value);
    if (err == ESP_OK)
        err = nvs_commit(handle);

    nvs_close(handle);
    ESP_LOGI(TAG, "Set %s/%s = %llu", namespace, key, (unsigned long long)value);
    return err;
}

esp_err_t nvs_util_get_u64(const char *namespace, const char *key, uint64_t *out_value)
{
    nvs_handle_t handle;
    esp_err_t err = nvs_open(namespace, NVS_READONLY, &handle);
    if (err != ESP_OK)
        return err;

    err = nvs_get_u64(handle, key, out_value);
    nvs_close(handle);
    if (err == ESP_OK)
        ESP_LOGI(TAG, "Get %s/%s = %llu", namespace, key, (unsigned long long)*out_value);
    return err;
}

esp_err_t nvs_util_set_i32(const char *namespace, const char *key, int32_t value)
{
    nvs_handle_t handle;
    esp_err_t err = nvs_open(namespace, NVS_READWRITE, &handle);
    if (err != ESP_OK)
        return err;

    err = nvs_set_i32(handle, key, value);
    if (err == ESP_OK)
        err = nvs_commit(handle);

    nvs_close(handle);
    ESP_LOGI(TAG, "Set %s/%s = %d", namespace, key, value);
    return err;
}

esp_err_t nvs_util_get_i32(const char *namespace, const char *key, int32_t *out_value)
{
    nvs_handle_t handle;
    esp_err_t err = nvs_open(namespace, NVS_READONLY, &handle);
    if (err != ESP_OK)
        return err;

    err = nvs_get_i32(handle, key, out_value);
    nvs_close(handle);
    if (err == ESP_OK)
        ESP_LOGI(TAG, "Get %s/%s = %d", namespace, key, *out_value);
    return err;
}

esp_err_t nvs_util_set_str(const char *namespace, const char *key, const char *value)
{
    nvs_handle_t handle;
    esp_err_t err = nvs_open(namespace, NVS_READWRITE, &handle);
    if (err != ESP_OK)
        return err;

    err = nvs_set_str(handle, key, value);
    if (err == ESP_OK)
        err = nvs_commit(handle);

    nvs_close(handle);
    ESP_LOGI(TAG, "Set %s/%s = %s", namespace, key, value);
    return err;
}

esp_err_t nvs_util_get_str(const char *namespace, const char *key, char *out_value, size_t max_len)
{
    nvs_handle_t handle;
    esp_err_t err = nvs_open(namespace, NVS_READONLY, &handle);
    if (err != ESP_OK)
        return err;

    size_t required_size = max_len;
    err = nvs_get_str(handle, key, out_value, &required_size);
    nvs_close(handle);
    if (err == ESP_OK)
        ESP_LOGI(TAG, "Get %s/%s = %s", namespace, key, out_value);
    return err;
}

esp_err_t nvs_util_erase_key(const char *namespace, const char *key)
{
    nvs_handle_t handle;
    esp_err_t err = nvs_open(namespace, NVS_READWRITE, &handle);
    if (err != ESP_OK)
        return err;

    err = nvs_erase_key(handle, key);
    if (err == ESP_OK)
        err = nvs_commit(handle);
    nvs_close(handle);
    ESP_LOGI(TAG, "Erased %s/%s", namespace, key);
    return err;
}