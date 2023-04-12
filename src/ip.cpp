#include "ip.h"

#include "arp.h"
#include "binary_trie.h"
#include "ethernet.h"
#include "icmp.h"
#include "log.h"
#include "my_buf.h"
#include "utils.h"

/**
 * Root node of IP routing table
 */
binary_trie_node<ip_route_entry> *ip_fib;

/**
 * Compare if the subnet contains IP addresses
 * @param subnet_prefix
 * @param subnet_mask
 * @param target_address
 * @return
 */
bool in_subnet(uint32_t subnet_prefix, uint32_t subnet_mask,
               uint32_t target_address) {
  return ((target_address & subnet_mask) == (subnet_prefix & subnet_mask));
}

/**
 * Processing IP packets addressed to myself
 * @param input_dev
 * @param ip_packet
 * @param len
 */
void ip_input_to_ours(net_device *input_dev, ip_header *ip_packet, size_t len) {
  // Transition to upper protocol processing
  switch (ip_packet->protocol) {
    case IP_PROTOCOL_NUM_ICMP:
      return icmp_input(ntohl(ip_packet->src_addr), ntohl(ip_packet->dest_addr),
                        ((uint8_t *)ip_packet) + IP_HEADER_SIZE,
                        len - IP_HEADER_SIZE);

    case IP_PROTOCOL_NUM_UDP:
      send_icmp_destination_unreachable(
          ntohl(ip_packet->src_addr), input_dev->ip_dev->address,
          ICMP_DESTINATION_UNREACHABLE_CODE_PORT_UNREACHABLE, ip_packet, len);
      return;
    case IP_PROTOCOL_NUM_TCP:
      return;
    default:

      LOG_IP("Unhandled ip protocol %04x", ip_packet->protocol);
      return;
  }
}

/**
 * Receiving and processing IP packets
 * @param input_dev
 * @param buffer
 * @param len
 */
void ip_input(net_device *input_dev, uint8_t *buffer, ssize_t len) {
  // Ignore incoming from interfaces without IP addresses
  if (input_dev->ip_dev == nullptr or input_dev->ip_dev->address == 0) {
    return;
  }

  // Dropped if shorter than IP header length
  if (len < sizeof(ip_header)) {
    LOG_IP("Received IP packet too short from %s\n", input_dev->name);
    return;
  }

  // Cast and handle buffers sent
  auto *ip_packet = reinterpret_cast<ip_header *>(buffer);

  LOG_IP("Received IP packet type %d from %s to %s\n", ip_packet->protocol,
         ip_ntoa(ip_packet->src_addr), ip_ntoa(ip_packet->dest_addr));

  if (ip_packet->version != 4) {
    LOG_IP("Incorrect IP version\n");
    return;
  }

  // Drop if IP header option is attached
  if (ip_packet->header_len != (sizeof(ip_header) >> 2)) {
    LOG_IP("IP header option is not supported\n");
    return;
  }

  if (ip_packet->dest_addr ==
      IP_ADDRESS_LIMITED_BROADCAST) {  // If the destination address is a
                                       // broadcast address
    return ip_input_to_ours(
        input_dev, ip_packet,
        len);  // Treated as a communication addressed to you
  }

  // Find out if the router has the destination IP address.
  for (net_device *dev = net_dev_list; dev; dev = dev->next) {
    if (dev->ip_dev != nullptr and
        dev->ip_dev->address != IP_ADDRESS(0, 0, 0, 0)) {
      // Processing when the destination IP address is an IP address owned by
      // the router or a directed broadcast address
      if (dev->ip_dev->address == ntohl(ip_packet->dest_addr) or
          dev->ip_dev->broadcast == ntohl(ip_packet->dest_addr)) {
        return ip_input_to_ours(
            dev, ip_packet,
            len);  // Treated as a communication addressed to you
      }
    }
  }
  // forwarding if the destination IP address is not an IP address that the
  // router has
  ip_route_entry *route = binary_trie_search(
      ip_fib, ntohl(ip_packet->dest_addr));  // look up routing table
  if (route ==
      nullptr) {  // discard the packet if there is no route to the destination
    LOG_IP("No route to %s\n", ip_htoa(ntohl(ip_packet->dest_addr)));
    // Drop packet
    return;
  }

  if (ip_packet->ttl <= 1) {  // drop if TTL is less than 1
    send_icmp_time_exceeded(
        ntohl(ip_packet->src_addr), input_dev->ip_dev->address,
        ICMP_TIME_EXCEEDED_CODE_TIME_TO_LIVE_EXCEEDED, buffer, len);
    return;
  }

  // set TTL to 1
  ip_packet->ttl--;

  // recalculate IP header checksum
  ip_packet->header_checksum = 0;
  ip_packet->header_checksum =
      checksum_16(reinterpret_cast<uint16_t *>(buffer), sizeof(ip_header));

  // copy to my_buf structure
  my_buf *ip_fwd_mybuf = my_buf::create(len);
  memcpy(ip_fwd_mybuf->buffer, buffer, len);
  ip_fwd_mybuf->len = len;

  if (route->type == connected) {  // if it is a direct connection network route
    ip_output_to_host(route->dev, ntohl(ip_packet->dest_addr),
                      ntohl(ip_packet->src_addr),
                      ip_fwd_mybuf);  // send directly to host
    return;

  } else if (route->type ==
             network) {  // if not a direct connection network route
    ip_output_to_next_hop(route->next_hop, ip_fwd_mybuf);  // send to next hop
    return;
  }
}

/**
 * Send IP packets directly to host via Ethernet
 * @param dev
 * @param dest_addr
 * @param src_addr
 * @param buffer
 */
void ip_output_to_host(net_device *dev, uint32_t dest_addr, uint32_t src_addr,
                       my_buf *buffer) {
  arp_table_entry *entry =
      search_arp_table_entry(dest_addr);  // search ARP table

  if (!entry) {  // if there is no ARP entry
    LOG_IP("Trying ip output to host, but no arp record to %s\n",
           ip_htoa(dest_addr));
    send_arp_request(dev, dest_addr);   // send ARP request
    my_buf::my_buf_free(buffer, true);  // Drop packet
    return;
  } else {
    ethernet_encapsulate_output(
        entry->dev, entry->mac_addr, buffer,
        ETHER_TYPE_IP);  // encapsulate and send over Ethernet
  }
}

/**
 * Send IP packets to NextHop
 * @param next_hop
 * @param buffer
 */
void ip_output_to_next_hop(uint32_t next_hop, my_buf *buffer) {
  arp_table_entry *entry =
      search_arp_table_entry(next_hop);  // search ARP table

  if (!entry) {  // if there is no ARP entry
    LOG_IP("Trying ip output to next hop, but no arp record to %s\n",
           ip_htoa(next_hop));

    ip_route_entry *route_to_next_hop =
        binary_trie_search(ip_fib, next_hop);  // look up routing table

    if (route_to_next_hop == nullptr or
        route_to_next_hop->type != connected) {  // if next hop is not reachable
      LOG_IP("Next hop %s is not reachable\n", ip_htoa(next_hop));
    } else {
      send_arp_request(route_to_next_hop->dev, next_hop);  // send ARP request
    }
    my_buf::my_buf_free(buffer, true);  // Drop packet
    return;

  } else {  // if there is an ARP entry and the MAC address is obtained
    ethernet_encapsulate_output(
        entry->dev, entry->mac_addr, buffer,
        ETHER_TYPE_IP);  // encapsulate with Ethernet and send
  }
}

/**
 * Send IP packets.
 * @param dest_addr
 * @param src_addr
 * @param buffer
 */
void ip_output(uint32_t dest_addr, uint32_t src_addr, my_buf *buffer) {
  // Find a route to the destination IP address
  ip_route_entry *route = binary_trie_search(ip_fib, dest_addr);
  if (route == nullptr) {  // if no route is found
    LOG_IP("No route to %s\n", ip_htoa(dest_addr));
    my_buf::my_buf_free(buffer, true);  // Drop packet
    return;
  }

  if (route->type == connected) {  // if it is a directly connected network
    ip_output_to_host(route->dev, dest_addr, src_addr, buffer);
    return;
  } else if (route->type ==
             network) {  // if it is not directly connected network
    ip_output_to_next_hop(route->next_hop, buffer);
    return;
  }
}

/**
 * Encapsulated in IP packets and sent
 * @param dest_addr Destination IP address
 * @param src_addr Source IP address
 * @param payload_mybuf Top of the my_buf structure to be wrapped and sent
 * @param protocol_num IP protocol number
 */
void ip_encapsulate_output(uint32_t dest_addr, uint32_t src_addr,
                           my_buf *payload_mybuf, uint8_t protocol_num) {
  // Calculate the total length of IP packets required by the IP header by
  // following the concatenated list
  uint16_t total_len = 0;
  my_buf *current = payload_mybuf;
  while (current != nullptr) {
    total_len += current->len;
    current = current->next;
  }

  // Allocate buffers for IP headers
  my_buf *ip_mybuf = my_buf::create(IP_HEADER_SIZE);
  payload_mybuf->add_header(
      ip_mybuf);  // Concatenate as a header to the data to be wrapped and sent

  // Set each IP header item
  auto *ip_buf = reinterpret_cast<ip_header *>(ip_mybuf->buffer);
  ip_buf->version = 4;
  ip_buf->header_len = sizeof(ip_header) >> 2;
  ip_buf->tos = 0;
  ip_buf->total_len = htons(sizeof(ip_header) + total_len);
  ip_buf->protocol = protocol_num;  // 8bit

  static uint16_t id = 0;
  ip_buf->identify = id++;
  ip_buf->frag_offset = 0;
  ip_buf->ttl = 0xff;
  ip_buf->header_checksum = 0;
  ip_buf->dest_addr = htonl(dest_addr);
  ip_buf->src_addr = htonl(src_addr);
  ip_buf->header_checksum = checksum_16(
      reinterpret_cast<uint16_t *>(ip_mybuf->buffer), ip_mybuf->len);

  for (net_device *dev = net_dev_list; dev; dev = dev->next) {
    if (dev->ip_dev == nullptr or
        dev->ip_dev->address == IP_ADDRESS(0, 0, 0, 0))
      continue;
    if (in_subnet(dev->ip_dev->address, dev->ip_dev->netmask, dest_addr)) {
      arp_table_entry *entry;
      entry = search_arp_table_entry(dest_addr);
      if (entry == nullptr) {
        LOG_IP("Trying ip output, but no arp record to %s\n",
               ip_htoa(dest_addr));
        send_arp_request(dev, dest_addr);
        my_buf::my_buf_free(payload_mybuf, true);
        return;
      }
      ethernet_encapsulate_output(dev, entry->mac_addr, ip_mybuf,
                                  ETHER_TYPE_IP);
    }
  }
}