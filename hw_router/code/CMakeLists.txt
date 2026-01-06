cmake_minimum_required(VERSION 3.12)

set(target_name Pico-RJ45-Sock_hello_world)

include(pico_sdk_import.cmake)
#project(${target_name})
project(${target_name} C CXX ASM)  # Add CXX here to enable C++
set(CMAKE_C_STANDARD 17)
set(CMAKE_CXX_STANDARD 20)

pico_sdk_init()

add_executable(${target_name} tft.cpp tft.hpp)

pico_generate_pio_header(${target_name} ${CMAKE_CURRENT_LIST_DIR}/ser_10base_t.pio)
pico_generate_pio_header(${target_name} ${CMAKE_CURRENT_LIST_DIR}/des_10base_t.pio)

target_sources(${target_name} PRIVATE
    main.cpp
    hwinit.c
    eth.c
    udp.c
    arp.c
    icmp.c
    tucp.c
    tft.cpp
    )

add_subdirectory(displaylib_16bit_PICO)

target_link_libraries(${target_name} PRIVATE
    pico_stdlib
    hardware_pio
    hardware_irq
    hardware_dma
    pico_multicore
    hardware_spi
    pico_displaylib_16
    )

# enable usb output, disable uart output
pico_enable_stdio_usb(${target_name} 1)
pico_enable_stdio_uart(${target_name} 0)

# Default binaries to Copy code to RAM when booting from flash.
# Code execution speed may improve, but code size is limited by RAM capacity.
pico_set_binary_type(${target_name} copy_to_ram)

pico_add_extra_outputs(${target_name})
