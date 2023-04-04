#include "device.h"

#include <sys/socket.h>

#include <iostream>

#include "ethernet.h"
#include "ip.h"
#include "net.h"

/**
 * Transmission process for net devices
 * @param dev Device used for transmission
 * @param buffer Buffer to send
 * @param len Length of buffer
 */
int net_device_transmit(struct net_device *dev, uint8_t *buffer, size_t len) {
  // Send through socket
  send(((net_device_data *)dev->data)->fd, buffer, len, 0);
  return 0;
}

/**
 * Receiving process for network devices
 * @param dev Device attempting to receive
 */
int net_device_poll(net_device *dev) {
  uint8_t recv_buffer[1550];
  // Received from socket
  ssize_t n = recv(((net_device_data *)dev->data)->fd, recv_buffer,
                   sizeof(recv_buffer), 0);
  if (n == -1) {
    if (errno == EAGAIN) {  // If there is no data to receive
      return 0;
    } else {
      return -1;  // Any other error.
    }
  }

  // Send received data to Ethernet
  ethernet_input(dev, recv_buffer, n);
  return 0;
}

// net_device *create_device(char *name,
//                           int (*transmit)(net_device *dev, uint8_t *buffer,
//                                           size_t len),
//                           uint8_t *macaddr, uint32_t address) {
//   auto *dev =
//       (net_device *)calloc(1, sizeof(net_device) + sizeof(net_device_data));
//   strcpy(dev->name, name);
//   dev->ops.transmit = transmit;
//   memcpy(dev->mac_addr, macaddr, 6);
//   ip_device *ip_dev;
//   ip_dev->address = address;
//   return dev;
// }