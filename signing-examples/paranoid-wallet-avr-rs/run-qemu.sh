#! /bin/bash

qemu-system-avr -M uno -bios target/avr-atmega328p/release/arduino-lib.elf -nographic -serial tcp::5678,server=on
#echo "running in Arduino Mega"
#qemu-system-avr -M mega -bios target/avr-atmega328p/release/arduino-lib.elf -nographic -serial tcp::5678,server=on
