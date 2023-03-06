#ifndef INTERFACE_H
#define INTERFACE_H

#include <cstdint>

#define IGNORE_INTERFACES {"lo", "bond0", "dummy0", "tunl0", "sit0"}

bool is_ignore_interface(const char *ifname);

#endif //INTERFACE_H