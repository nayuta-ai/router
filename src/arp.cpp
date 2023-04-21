#include "../include/arp.h"

#include <cstring>

#include "ethernet.h"
#include "ip.h"
#include "log.h"
#include "my_buf.h"
#include "net.h"
#include "utils.h"

arp_table_entry arp_table[ARP_TABLE_SIZE];

/**
 * Adding and updating entries in the ARP table
 * @param dev
 * @param mac_addr
 * @param ip_addr
 */
void add_arp_table_entry(net_device *dev, uint8_t *mac_addr, uint32_t ip_addr) {
  // The first candidate location is the one whose hash of IP addresses in the
  // Hash table is index
  const uint32_t index = ip_addr % ARP_TABLE_SIZE;
  arp_table_entry *candidate = &arp_table[index];

  // Check if it can be put in the table
  if (candidate->ip_addr == 0 or
      candidate->ip_addr ==
          ip_addr) {  // When you are put in the first candidate place
    // Set entries
    memcpy(candidate->mac_addr, mac_addr, 6);
    candidate->ip_addr = ip_addr;
    candidate->dev = dev;
    LOG_ARP("Add arp table entry: ip_addr=%s, mac_addr=%s\n", ip_htoa(ip_addr),
            mac_addr_toa(mac_addr));
    return;
  }

  // If not put in, concatenate to the entry in the candidate
  while (candidate->next != nullptr) {  // Trace to the end of the chained list
    candidate = candidate->next;
    // If there is an entry for the same IP address along the way, update that
    // entry.
    if (candidate->ip_addr == ip_addr) {
      memcpy(candidate->mac_addr, mac_addr, 6);
      candidate->ip_addr = ip_addr;
      candidate->dev = dev;
      return;
    }
  }

  // Create a new entry at the end of the chained list
  candidate->next = (arp_table_entry *)calloc(1, sizeof(arp_table_entry));
  memcpy(candidate->next->mac_addr, mac_addr, 6);
  candidate->next->ip_addr = ip_addr;
  candidate->next->dev = dev;
}

/**
 * Search ARP table
 * @param ip_addr
 * @return
 */
arp_table_entry *search_arp_table_entry(uint32_t ip_addr) {
  // The first candidate location is the one whose hash of IP addresses in the
  // Hash table is index
  arp_table_entry *candidate = &arp_table[ip_addr % ARP_TABLE_SIZE];

  if (candidate->ip_addr == ip_addr) {  // If the candidate entry is from the IP
                                        // address you are searching for
    return candidate;
  } else if (candidate->ip_addr ==
             0) {  // If the candidate entry was not registered
    return nullptr;
  }

  // If the candidate entry is not for the target IP address, check the
  // consolidated list for that entry
  while (candidate->next != nullptr) {
    candidate = candidate->next;
    if (candidate->ip_addr == ip_addr) {  // If the IP address searching for in
                                          // the consolidated list exists
      return candidate;
    }
  }

  // If it is not found in the consolidated list
  return nullptr;
}

/**
 * Output ARP tables
 */
void dump_arp_table_entry() {
  printf(
      "|---IP ADDRESS----|----MAC ADDRESS----|------DEVICE-------|-INDEX-|\n");
  for (int i = 0; i < ARP_TABLE_SIZE; ++i) {
    if (arp_table[i].ip_addr == 0) {
      continue;
    }
    // Output a concatenated list of entries in sequence
    for (arp_table_entry *entry = &arp_table[i]; entry; entry = entry->next) {
      printf("| %15s | %14s | %17s |  %04d |\n", ip_htoa(entry->ip_addr),
             mac_addr_toa(entry->mac_addr), entry->dev->name, i);
    }
  }
  printf(
      "|-----------------|-------------------|-------------------|-------|\n");
}

/**
 * Sends an ARP request.
 * @param dev The network device to send the request from.
 * @param ip_addr The IP address of the host to search for.
 */
void send_arp_request(net_device *dev, uint32_t ip_addr) {
  LOG_ARP("Sending arp request via %s for %s\n", dev->name, ip_htoa(ip_addr));

  // Create a buffer to hold the ARP message
  auto *arp_mybuf = my_buf::create(ARP_ETHERNET_PACKET_LEN);

  // Get a pointer to the ARP message inside the buffer
  auto *arp_msg = reinterpret_cast<arp_ip_to_ethernet *>(arp_mybuf->buffer);

  // Set the ARP message fields
  arp_msg->htype = htons(ARP_HTYPE_ETHERNET);  // Set the hardware type
  arp_msg->ptype = htons(ETHER_TYPE_IP);       // Set the protocol type
  arp_msg->hlen = ETHERNET_ADDRESS_LEN;  // Set the hardware address length
  arp_msg->plen = IP_ADDRESS_LEN;        // Set the protocol address length
  arp_msg->op = htons(ARP_OPERATION_CODE_REQUEST);  // Set the operation code
  memcpy(arp_msg->sha, dev->mac_addr,
         6);  // Set the sender hardware address to the device's MAC address
  arp_msg->spa =
      htonl(dev->ip_dev->address);  // Set the sender protocol address to the
                                    // device's IP address
  arp_msg->tpa = htonl(ip_addr);    // Set the target protocol address to the IP
                                    // address of the host to search for

  // Encapsulate the ARP message in an Ethernet frame and send it
  ethernet_encapsulate_output(dev, ETHERNET_ADDRESS_BROADCAST, arp_mybuf,
                              ETHER_TYPE_ARP);
}

/**
 * Receiving and processing ARP packets
 * @param input_dev
 * @param buffer
 * @param len
 */
void arp_input(net_device *input_dev, uint8_t *buffer, ssize_t len) {
  // If the ARP packet is shorter than expected.
  if (len < sizeof(arp_ip_to_ethernet)) {
    LOG_ARP("Too short arp packet\n");
    return;
  }

  auto *arp_msg = reinterpret_cast<arp_ip_to_ethernet *>(buffer);
  uint16_t op = ntohs(arp_msg->op);

  switch (ntohs(arp_msg->ptype)) {
    case ETHER_TYPE_IP:

      if (arp_msg->hlen != ETHERNET_ADDRESS_LEN) {
        LOG_ARP("Illegal hardware address length\n");
        return;
      }

      if (arp_msg->plen != IP_ADDRESS_LEN) {
        LOG_ARP("Illegal protocol address length\n");
        return;
      }

      // Branching by operation code
      if (op == ARP_OPERATION_CODE_REQUEST) {
        // Receipt of ARP request
        arp_request_arrives(input_dev, arp_msg);
        dump_arp_table_entry();
        return;
      } else if (op == ARP_OPERATION_CODE_REPLY) {
        // Receipt of ARP reply
        arp_reply_arrives(input_dev, arp_msg);
        dump_arp_table_entry();
        return;
      }
      break;
  }
}

/**
 * Receiving and processing ARP request packets
 * @param dev
 * @param request
 */
void arp_request_arrives(net_device *dev, arp_ip_to_ethernet *request) {
  if (dev->ip_dev != nullptr and
      dev->ip_dev->address !=
          IP_ADDRESS(0, 0, 0,
                     0)) {  // If it was received from a device with a
                            // configured IP address
    if (dev->ip_dev->address ==
        ntohl(request->tpa)) {  // If the address being requested is itself.
      LOG_ARP("Sending arp reply via %s\n", ip_ntoa(request->tpa));

      auto *reply_mybuf = my_buf::create(ARP_ETHERNET_PACKET_LEN);

      auto reply_msg =
          reinterpret_cast<arp_ip_to_ethernet *>(reply_mybuf->buffer);
      reply_msg->htype = htons(ARP_HTYPE_ETHERNET);
      reply_msg->ptype = htons(ETHER_TYPE_IP);
      reply_msg->hlen = ETHERNET_ADDRESS_LEN;  // IP address length
      reply_msg->plen = IP_ADDRESS_LEN;        // MAC address length
      reply_msg->op = htons(ARP_OPERATION_CODE_REPLY);

      // Write reply information
      memcpy(reply_msg->sha, dev->mac_addr, ETHERNET_ADDRESS_LEN);
      reply_msg->spa = htonl(dev->ip_dev->address);
      memcpy(reply_msg->tha, request->sha, ETHERNET_ADDRESS_LEN);
      reply_msg->tpa = request->spa;

      ethernet_encapsulate_output(
          dev, request->sha, reply_mybuf,
          ETHER_TYPE_ARP);  // Transmission over Ethernet
      add_arp_table_entry(
          dev, request->sha,
          ntohl(request->spa));  // Generate entries from ARP requests as well
      return;
    }
  }
}

/**
 * Receiving and processing ARP reply packets
 * @param dev
 * @param reply
 */
void arp_reply_arrives(net_device *dev, arp_ip_to_ethernet *reply) {
  if (dev->ip_dev != nullptr and
      dev->ip_dev->address !=
          IP_ADDRESS(0, 0, 0,
                     0)) {  // If it was received from a device with a
                            // configured IP address
    LOG_ARP("Added arp table entry by arp reply (%s => %s)\n",
            ip_ntoa(reply->spa), mac_addr_toa(reply->sha));
    add_arp_table_entry(dev, reply->sha,
                        ntohl(reply->spa));  // Adding ARP table entries
  }
}