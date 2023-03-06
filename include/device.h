#ifndef NET_DEVICE_H
#define NET_DEVICE_H

#include <cstdint>
#include <cstring>

int net_device_transmit(struct net_device *dev,
                        uint8_t *buffer, size_t len);
int net_device_poll(net_device *dev);

#endif //NET_DEVICE_H