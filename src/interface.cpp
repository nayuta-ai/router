#include <cstring>
#include <net/if.h>

#include "../include/interface.h"

/**
 * Return whether the device to ignore
 * @param ifname
 * @return Whether included in IGNORE_INTERFACES
 */
bool is_ignore_interface(const char *ifname){
    char ignore_interfaces[][IF_NAMESIZE] = IGNORE_INTERFACES;
    for(int i = 0; i < sizeof(ignore_interfaces) / IF_NAMESIZE; i++){
        if(strcmp(ignore_interfaces[i], ifname) == 0){
            return true;
        }
    }
    return false;
}