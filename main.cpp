#include <arpa/inet.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <linux/if_ether.h>
#include <net/if.h>
#include <netpacket/packet.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <termios.h>
#include <unistd.h>

#include <cstdint>
#include <iostream>

#include "arp.h"
#include "binary_trie.h"
#include "device.h"
#include "interface.h"
#include "ip.h"
#include "log.h"
#include "net.h"

/* Entry Point */
int main() {
  struct ifreq ifr {};
  struct ifaddrs *addrs;

  // Fetch information of network interface
  getifaddrs(&addrs);

  for (ifaddrs *tmp = addrs; tmp; tmp = tmp->ifa_next) {
    if (tmp->ifa_addr && tmp->ifa_addr->sa_family == AF_PACKET) {
      // Set the interface to be controlled by ioctl
      memset(&ifr, 0, sizeof(ifr));
      strcpy(ifr.ifr_name, tmp->ifa_name);

      // Check whether the ignore interface is
      if (is_ignore_interface(tmp->ifa_name)) {
        printf("Skipped to enable interface %s\n", tmp->ifa_name);
        continue;
      }

      // Open socket
      int sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
      if (sock == -1) {
        LOG_ERROR("socket open failed: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
      }

      // Get the index of the interface
      if (ioctl(sock, SIOCGIFINDEX, &ifr) == -1) {
        LOG_ERROR("ioctl SIOCGIFINDEX failed: %s\n", strerror(errno));
        close(sock);
        exit(EXIT_FAILURE);
      }

      // Bind the interface into the socket
      sockaddr_ll addr{};
      memset(&addr, 0x00, sizeof(addr));
      addr.sll_family = AF_PACKET;
      addr.sll_protocol = htons(ETH_P_ALL);
      addr.sll_ifindex = ifr.ifr_ifindex;
      if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
        LOG_ERROR("bind failed: %s\n", strerror(errno));
        close(sock);
        exit(EXIT_FAILURE);
      }

      // Get the MAC address of the interface
      if (ioctl(sock, SIOCGIFHWADDR, &ifr) == -1) {
        LOG_ERROR("ioctl SIOCGIFHWADDR failed: %s\n", strerror(errno));
        close(sock);
        continue;
      }

      // Create net_device structure
      auto *dev = (net_device *)calloc(
          1, sizeof(net_device) +
                 sizeof(net_device_data));  // Allocate an area for net_device
                                            // and an area for net_device_data
      dev->ops.transmit = net_device_transmit;  // Setting function for transmit
      dev->ops.poll = net_device_poll;          // Setting function for received

      strcpy(dev->name, tmp->ifa_name);  // Set interface name to net_device
      memcpy(dev->mac_addr, &ifr.ifr_hwaddr.sa_data[0],
             6);  // Set MAC address in net_device
      ((net_device_data *)dev->data)->fd = sock;

      printf(
          "Created device %s socket %d address %02x:%02x:%02x:%02x:%02x:%02x "
          "\n",
          dev->name, sock, dev->mac_addr[0], dev->mac_addr[1], dev->mac_addr[2],
          dev->mac_addr[3], dev->mac_addr[4], dev->mac_addr[5]);

      // Concatenate to the net_device concatenation list
      net_device *next;
      next = net_dev_list;
      net_dev_list = dev;
      dev->next = next;

      // Set to non-blocking
      int val = fcntl(sock, F_GETFL, 0);  // Get the flag of file descriptor
      fcntl(sock, F_SETFL, val | O_NONBLOCK);  // Set the Non blocking bit
    }
  }
  // Release allocated memory
  freeifaddrs(addrs);

  // Exit if none of the enabled interfaces are found
  if (net_dev_list == nullptr) {
    LOG_ERROR("No interface is enabled!\n");
    exit(EXIT_FAILURE);
  }

  // Create root node of IP routing table tree structure
  ip_fib = (binary_trie_node<ip_route_entry> *)calloc(
      1, sizeof(binary_trie_node<ip_route_entry>));

  // Input network settings
  configure();

  // Set to receive input immediately without buffering
  termios attr{};
  tcgetattr(0, &attr);
  attr.c_lflag &= ~ICANON;
  attr.c_cc[VTIME] = 0;
  attr.c_cc[VMIN] = 1;
  tcsetattr(0, TCSANOW, &attr);
  fcntl(0, F_SETFL, O_NONBLOCK);  // Non-blocking settings for standard input

  while (true) {
    int input = getchar();  // Receive input
    if (input != -1) {      // If there is an input
      printf("\n");
      if (input == 'a')
        dump_arp_table_entry();
      else if (input == 'q')
        break;
    }
    // Receive communication from device
    for (net_device *dev = net_dev_list; dev; dev = dev->next) {
      dev->ops.poll(dev);
    }
  }
  printf("Goodbye!\n");
  return 0;
}