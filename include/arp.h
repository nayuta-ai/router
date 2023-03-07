#ifndef CURO_ARP_H
#define CURO_ARP_H

#include <iostream>

#define ARP_HTYPE_ETHERNET 0x0001

#define ARP_OPERATION_CODE_REQUEST 0x0001
#define ARP_OPERATION_CODE_REPLY 0x0002

#define ARP_ETHERNET_PACKET_LEN 46

#define ARP_TABLE_SIZE 1111

struct net_device;

struct arp_table_entry {
  uint8_t mac_addr[6];
  uint32_t ip_addr;
  net_device *dev;
  arp_table_entry *next;
};

void add_arp_table_entry(net_device *dev, uint8_t *mac_addr, uint32_t ip_addr);

arp_table_entry *search_arp_table_entry(uint32_t ip_addr);

void dump_arp_table_entry();

void send_arp_request(net_device *dev, uint32_t ip_addr);

struct arp_ip_to_ethernet {
  uint16_t htype;  // Hardware Type
  uint16_t ptype;  // Protocol Type
  uint8_t hlen;    // Hardware address books
  uint8_t plen;    // Protocol address books
  uint16_t op;     // Operation code
  uint8_t sha[6];  // Hardware address of sender
  uint32_t spa;    // Protocol address of the sender
  uint8_t tha[6];  // Target hardware address
  uint32_t tpa;    // Target protocol address
} __attribute__((packed));

void arp_request_arrives(net_device *dev, arp_ip_to_ethernet *request);
void arp_reply_arrives(net_device *dev, arp_ip_to_ethernet *reply);

void arp_input(net_device *input_dev, uint8_t *buffer, ssize_t len);

#endif  // CURO_ARP_H