#!/bin/bash

qemu-system-x86_64 -serial mon:stdio -kernel ./bzImage -initrd ./initramfs.cpio.gz -m 128 -append "console=ttyS0"
