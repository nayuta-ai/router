
#include "ethernet.h"

#include "arp.h"
#include "ip.h"
#include "log.h"
#include "my_buf.h"
#include "utils.h"

/**
 * Receive process for Ethernet
 * @param dev Received devices
 * @param buffer Byte sequence of data received
 * @param len Length of data received
 */
void ethernet_input(net_device *dev, uint8_t *buffer, ssize_t len) {
  // Interpret sent communications as Ethernet frames
  auto *header = reinterpret_cast<ethernet_header *>(buffer);
  uint16_t ether_type =
      ntohs(header->type);  // Extract Ethertype and convert to host byte order

  // Check whether the communication is to your MAC address or a broadcast
  // communication
  if (memcmp(header->dest_addr, dev->mac_addr, 6) != 0 and
      memcmp(header->dest_addr, ETHERNET_ADDRESS_BROADCAST, 6) != 0) {
    return;
  }

  LOG_ETHERNET("Received ethernet frame type %04x from %s to %s\n", ether_type,
               mac_addr_toa(header->src_addr), mac_addr_toa(header->dest_addr));

  // Identify the upper protocol from the Ethertype value
  switch (ether_type) {
    case ETHER_TYPE_ARP:  // If the Ethertype was an ARP one.
      return arp_input(dev, buffer + ETHERNET_HEADER_SIZE,
                       len - ETHERNET_HEADER_SIZE);  // Remove Ethernet header
                                                     // and go to ARP process
    case ETHER_TYPE_IP:  // If the Ethertype was an IP one.
      return ip_input(dev, buffer + ETHERNET_HEADER_SIZE,
                      len - ETHERNET_HEADER_SIZE);  // Remove Ethernet header
                                                    // and go to IP process
    default:  // If it's an Ethertype you don't know
      LOG_ETHERNET("Received unhandled ether type %04x\n", ether_type);
      return;
  }
}

/**
 * Encapsulated and transmitted over Ethernet
 * @param dev Transmitting device
 * @param dest_addr Destination address
 * @param payload_mybuf Top of the my_buf structure to be wrapped and sent
 * @param ether_type Ethertype
 */
void ethernet_encapsulate_output(net_device *dev, const uint8_t *dest_addr,
                                 my_buf *payload_mybuf, uint16_t ether_type) {
  LOG_ETHERNET("Sending ethernet frame type %04x from %s to %s\n", ether_type,
               mac_addr_toa(dev->mac_addr), mac_addr_toa(dest_addr));

  my_buf *header_mybuf = my_buf::create(
      ETHERNET_HEADER_SIZE);  // Buffer for Ethernet header length
  auto *header = reinterpret_cast<ethernet_header *>(header_mybuf->buffer);

  // Ethernet Header Settings
  memcpy(header->src_addr, dev->mac_addr,
         6);  // Set the device address as the source address
  memcpy(header->dest_addr, dest_addr, 6);  // Destination address settings
  header->type = htons(ether_type);         // Ethernettype settings

  payload_mybuf->add_header(
      header_mybuf);  // Header on buffer received from upper protocol

  uint8_t send_buffer[1550];
  // Expand buffer in memory while calculating total length
  size_t total_len = 0;
  my_buf *current = header_mybuf;
  while (current != nullptr) {
    if (total_len + current->len > sizeof(send_buffer)) {  // When Overflowing
      LOG_ETHERNET("Frame is too long!\n");
      return;
    }

    memcpy(&send_buffer[total_len], current->buffer, current->len);

    total_len += current->len;
    current = current->next;
  }

  // Send to network device
  dev->ops.transmit(dev, send_buffer, total_len);

  my_buf::my_buf_free(header_mybuf, true);  // memory leaching
}