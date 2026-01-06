#ifndef __TFT_HPP__
#define __TFT_HPP__

#include <stdint.h>

void tft_init(void);
void tft_hello_world(void);
void tft_display_buf(uint8_t *buf, uint32_t size);
void tft_ping_back(void);

#endif //__TFT_HPP__
