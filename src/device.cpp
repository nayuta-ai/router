#include <iostream>
#include <sys/socket.h>

#include "../include/net.h"
#include "../include/device.h"

/**
 * Transmission process for net devices
 * @param dev Device used for transmission
 * @param buffer Buffer to send
 * @param len Length of buffer
 */
int net_device_transmit(struct net_device *dev,
                        uint8_t *buffer, size_t len){
  // Send through socket
  send(((net_device_data *) dev->data)->fd,
        buffer, len, 0);
  return 0;
}

/**
 * Receiving process for network devices
 * @param dev Device attempting to receive
 */
int net_device_poll(net_device *dev){
  uint8_t recv_buffer[1550];
  // Received from socket
  ssize_t n = recv(
            ((net_device_data *) dev->data)->fd,
            recv_buffer,
            sizeof(recv_buffer), 0);
  if(n == -1){
    if(errno == EAGAIN){ // If there is no data to receive
      return 0;
    }else{
      return -1; // Any other error.
    }
  }

  printf("Received %lu bytes from %s: ",
           n, dev->name);
  for(int i = 0; i < n; ++i){
    printf("%02x", recv_buffer[i]);
  }
  printf("\n");
  return 0;
}