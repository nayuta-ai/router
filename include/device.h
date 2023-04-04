#ifndef NET_DEVICE_H
#define NET_DEVICE_H

#include <cstdint>
#include <cstring>

#include "net.h"

int net_device_transmit(struct net_device *dev, uint8_t *buffer, size_t len);
int net_device_poll(net_device *dev);
// net_device *create_device(char *name,
//                           int (*transmit)(net_device *dev, uint8_t *buffer,
//                                           size_t len),
//                           uint8_t *macaddr, uint32_t address);

#endif  // NET_DEVICE_H