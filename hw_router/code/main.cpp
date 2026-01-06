/********************************************************
* Title    : Pico-10BASE-T Sample
* Date     : 2022/08/22
* Design   : kingyo
********************************************************/
#include <stdio.h>
#include "pico/stdlib.h"
extern "C" {
#include "hwinit.h"
}

#include "eth.h"

#include "tft.hpp"

int main() {

    hw_init();

    stdio_init_all();

    tft_init();
    tft_hello_world();
    
    //stdio_usb_init();
    
    

    eth_init();


    printf("[BOOT]\r\n");

    hw_start_led_blink();

    while (1) {
        eth_main();
    }
}
