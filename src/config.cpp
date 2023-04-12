#include "config.h"

#include "binary_trie.h"
#include "ip.h"
#include "log.h"
#include "net.h"
#include "utils.h"

/**
 * Set route to device
 * @param prefix
 * @param prefix_len
 * @param next_hop
 */
void configure_ip_net_route(uint32_t prefix, uint32_t prefix_len,
                            uint32_t next_hop) {
  // Conversion between prefix length and netmask
  uint32_t mask = 0xffffffffff;
  mask <<= (32 - prefix_len);

  // Generate route entry
  ip_route_entry *entry;
  entry = (ip_route_entry *)(calloc(1, sizeof(ip_route_entry)));
  entry->type = network;
  entry->next_hop = next_hop;

  // register a route
  binary_trie_add(ip_fib, prefix & mask, prefix_len, entry);
}

/**
 * Set IP address for device
 * @param dev
 * @param address
 * @param netmask
 */
void configure_ip_address(net_device *dev, uint32_t address, uint32_t netmask) {
  if (dev == nullptr) {
    LOG_ERROR("Configure net dev not found\n");
    exit(EXIT_FAILURE);
  }

  // IP address registration
  dev->ip_dev = (ip_device *)calloc(1, sizeof(ip_device));
  dev->ip_dev->address = address;
  dev->ip_dev->netmask = netmask;
  dev->ip_dev->broadcast = (address & netmask) | (~netmask);

  printf("Set ip address to %s\n", dev->name);

  // Set IP address and direct connection route at the same time
  ip_route_entry *entry;
  entry = (ip_route_entry *)calloc(1, sizeof(ip_route_entry));
  entry->type = connected;
  entry->dev = dev;

  int len = 0;  // convert subnet mask and prefix length
  for (; len < 32; ++len) {
    if (!(netmask >> (31 - len) & 0b01)) {
      break;
    }
  }

  // set route for direct connection network
  binary_trie_add(ip_fib, address & netmask, len, entry);

  printf("Set directly connected route %s/%d via %s\n",
         ip_htoa(address & netmask), len, dev->name);
}
