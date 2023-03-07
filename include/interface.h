#ifndef INTERFACE_H
#define INTERFACE_H

#include <cstdint>

#include "net.h"

#define IGNORE_INTERFACES \
  { "lo", "bond0", "dummy0", "tunl0", "sit0" }

bool is_ignore_interface(const char *ifname);

net_device *get_net_device_by_name(const char *name);

void configure();

#endif  // INTERFACE_H