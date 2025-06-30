#include <sys/reboot.h>
#include <unistd.h>
#include <stdio.h>

int main() {
    //sync(); // flush filesystems
    if (reboot(RB_POWER_OFF) == -1) {
        perror("reboot");
        return 1;
    }
    return 0;
}
