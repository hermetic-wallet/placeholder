#ifndef __ARP_H__
#define __ARP_H__

#include <stdint.h>

// -------------------
// Preamble     7
// SFD          1
// Ether        14
// ARP Packet   46 (28 + padding 18)
// FCS          4
// -------------------
//              72
#define DEF_ARP_BUF_SIZE        (72)
//#define DEF_ARP_BUF_SIZE        (172)

#ifdef __cplusplus
extern "C" {
#endif
void arp_init(void);
void arp_packet_gen_10base(uint32_t *buf, uint64_t dst_mac, uint32_t sender_ip);
uint32_t arp_packet_remake_10base(uint32_t *buf, volatile uint32_t *in_data, uint32_t size);
#ifdef __cplusplus
}
#endif

#endif //__ARP_H__
