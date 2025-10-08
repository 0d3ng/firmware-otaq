#pragma once
#include "esp_adc/adc_oneshot.h"
#include "esp_adc/adc_cali.h"
#include "esp_adc/adc_cali_scheme.h"

// configuration for voltage divider
#define R1_OHM 10000.0f
#define R2_OHM 10000.0f

// initiaze ADC and calibration for battery voltage measurement
void battery_adc_init(adc_oneshot_unit_handle_t *adc_handle, adc_cali_handle_t *cali_handle, adc_channel_t channel);

// read battery voltage in volts, averaging 'samples' readings
float battery_read_voltage(adc_oneshot_unit_handle_t adc_handle, adc_cali_handle_t cali_handle, adc_channel_t channel, int samples);
