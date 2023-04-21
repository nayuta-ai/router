#include "interface.h"

#include <net/if.h>

#include <cstring>

#include "config.h"
#include "ip.h"
#include "net.h"

/**
 * Return whether the device to ignore
 * @param ifname
 * @return Whether included in IGNORE_INTERFACES
 */
bool is_ignore_interface(const char *ifname) {
  char ignore_interfaces[][IF_NAMESIZE] = IGNORE_INTERFACES;
  for (int i = 0; i < sizeof(ignore_interfaces) / IF_NAMESIZE; i++) {
    if (strcmp(ignore_interfaces[i], ifname) == 0) {
      return true;
    }
  }
  return false;
}

/**
 * Find devices by interface name
 * @param name Device name
 * @return
 */
net_device *get_net_device_by_name(const char *name) {
  net_device *dev;
  for (dev = net_dev_list; dev; dev = dev->next) {
    if (strcmp(dev->name, name) == 0) {
      return dev;
    }
  }
  return nullptr;
}

/**
 * Configure router settings
 */
void configure() {
  configure_ip_address(get_net_device_by_name("router1-br0"),
                       IP_ADDRESS(192, 168, 1, 1),
                       IP_ADDRESS(255, 255, 255, 0));
  configure_ip_address(get_net_device_by_name("router1-router2"),
                       IP_ADDRESS(192, 168, 0, 1),
                       IP_ADDRESS(255, 255, 255, 0));
  configure_ip_net_route(IP_ADDRESS(192, 168, 2, 0), 24,
                         IP_ADDRESS(192, 168, 0, 2));
  configure_ip_nat(get_net_device_by_name("router1-br0"),
                   get_net_device_by_name("router1-router2"));
}