#ifndef __TUCP_H__
#define __TUCP_H__

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif
void tucp_init(void);
uint32_t tucp_packet_remake_10base(uint32_t *buf, volatile uint32_t *in_data, uint32_t size, int32_t delta);
#ifdef __cplusplus
}
#endif

#endif //__TUCP_H__
