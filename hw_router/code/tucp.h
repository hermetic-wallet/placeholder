#ifndef __TUCP_H__
#define __TUCP_H__

#include <stdint.h>


void tucp_init(void);
uint32_t tucp_packet_remake_10base(uint32_t *buf, volatile uint32_t *in_data, uint32_t size);

#endif //__TUCP_H__
