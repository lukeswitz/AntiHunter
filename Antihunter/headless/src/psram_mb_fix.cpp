#ifdef ARDUINO_XIAO_ESP32C5
#include "esp_err.h"
#include "esp_psram.h"

extern "C" esp_err_t __real_esp_psram_mspi_mb_init(void);

extern "C" esp_err_t __wrap_esp_psram_mspi_mb_init(void) {
    return ESP_OK;
}

void ahPsramBarrierInit(void) {
    if (esp_psram_is_initialized())
        __real_esp_psram_mspi_mb_init();
}
#endif
