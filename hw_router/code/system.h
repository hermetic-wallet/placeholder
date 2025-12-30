#ifndef __SYSTEM_H__
#define __SYSTEM_H__

// Compile switch
#define UART_EBG_EN             (0)     // 有効にするとちょい重たい
#define FCS_DMA_EN              (1)     // FCSの計算にDMAを使用する
#define DEF_10BASET_FULL_EN     (0)     // Enable 10BASE-T Full Duplex


// RasPico Network settings
#define DEF_SYS_PICO_MAC        (0x123456789abc)


#define DEF_SYS_PICO_IP1        (172)
#define DEF_SYS_PICO_IP2        (16)
#define DEF_SYS_PICO_IP3        (3)
#define DEF_SYS_PICO_IP4        (2)


// For UDP
#define DEF_SYS_UDP_DST_MAC     (0x23456789abcd)



#define DEF_SYS_UDP_DST_IP1     (172)
#define DEF_SYS_UDP_DST_IP2     (16)
#define DEF_SYS_UDP_DST_IP3     (3)
#define DEF_SYS_UDP_DST_IP4     (1)


#endif //__SYSTEM_H__
