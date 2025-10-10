#include "battery_voltage.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"

void battery_adc_init(adc_oneshot_unit_handle_t *adc_handle,
                      adc_cali_handle_t *cali_handle,
                      adc_channel_t channel)
{
    // Inisialisasi ADC oneshot
    adc_oneshot_unit_init_cfg_t adc1_config = {
        .unit_id = ADC_UNIT_1,
        .ulp_mode = ADC_ULP_MODE_DISABLE};
    adc_oneshot_new_unit(&adc1_config, adc_handle);

    adc_oneshot_chan_cfg_t adc_channel_config = {
        .bitwidth = ADC_BITWIDTH_12,
        .atten = ADC_ATTEN_DB_11};
    adc_oneshot_config_channel(*adc_handle, channel, &adc_channel_config);

    // Inisialisasi kalibrasi ADC
    adc_cali_line_fitting_config_t cali_config = {
        .unit_id = ADC_UNIT_1,
        .atten = ADC_ATTEN_DB_11,
        .bitwidth = ADC_BITWIDTH_DEFAULT};
    adc_cali_create_scheme_line_fitting(&cali_config, cali_handle);
}

float battery_read_voltage(adc_oneshot_unit_handle_t adc_handle,
                           adc_cali_handle_t cali_handle,
                           adc_channel_t channel,
                           int samples)
{
    int32_t adc_sum = 0;
    for (int i = 0; i < samples; i++)
    {
        int raw;
        adc_oneshot_read(adc_handle, channel, &raw);
        adc_sum += raw;
        vTaskDelay(10 / portTICK_PERIOD_MS); // delay 10 ms
    }
    int32_t adc_avg = adc_sum / samples;

    int vout_mv;
    adc_cali_raw_to_voltage(cali_handle, adc_avg, &vout_mv); // langsung pakai handle
    ESP_LOGI("battery_voltage", "ADC raw avg: %d, Voltage: %d mV", adc_avg, vout_mv);
    float vout_v = vout_mv / 1000.0f;
    float vin_v = vout_v * ((R1_OHM + R2_OHM) / R2_OHM);
    return vin_v;
}
