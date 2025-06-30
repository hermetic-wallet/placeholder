#include <unistd.h>
#include <sys/syscall.h>
//#include <linux/reboot.h> // -I$LINUX_SRC/linux/include/uapi/
#include <stdio.h>
#include <errno.h>

int main() {
    //sync();

    //int ret = syscall(SYS_reboot, LINUX_REBOOT_MAGIC1, LINUX_REBOOT_MAGIC2, LINUX_REBOOT_CMD_POWER_OFF, NULL);
    int ret = syscall(SYS_reboot, 0xfee1dead, 672274793, 0x4321FEDC, NULL);

    if (ret == -1) {
        perror("syscall reboot");
        return 1;
    }
    return 0;
}
