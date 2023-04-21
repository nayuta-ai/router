#include "nat.h"

#include "icmp.h"
#include "ip.h"
#include "log.h"
#include "net.h"
#include "utils.h"

/**
 * Output NAT table
 */
void dump_nat_tables() {
  printf("|-PROTO-|---------LOCAL---------|--------GLOBAL---------|\n");
  for (net_device *dev = net_dev_list; dev; dev = dev->next) {
    if (dev->ip_dev != nullptr and dev->ip_dev->nat_dev != nullptr) {
      for (int i = 0; i < NAT_GLOBAL_PORT_SIZE; ++i) {
        if (dev->ip_dev->nat_dev->entries->tcp[i].global_port != 0) {
          printf("|  TCP  | %15s:%05d | %15s:%05d |\n",
                 ip_htoa(dev->ip_dev->nat_dev->entries->tcp[i].local_addr),
                 dev->ip_dev->nat_dev->entries->tcp[i].local_port,
                 ip_htoa(dev->ip_dev->nat_dev->entries->tcp[i].global_addr),
                 dev->ip_dev->nat_dev->entries->tcp[i].global_port);
        }
        if (dev->ip_dev->nat_dev->entries->udp[i].global_port != 0) {
          printf("|  UDP  | %15s:%05d | %15s:%05d |\n",
                 ip_htoa(dev->ip_dev->nat_dev->entries->udp[i].local_addr),
                 dev->ip_dev->nat_dev->entries->udp[i].local_port,
                 ip_htoa(dev->ip_dev->nat_dev->entries->udp[i].global_addr),
                 dev->ip_dev->nat_dev->entries->udp[i].global_port);
        }
      }
      for (int i = 0; i < NAT_ICMP_ID_SIZE; ++i) {
        if (dev->ip_dev->nat_dev->entries->icmp[i].local_addr != 0) {
          printf("|  ICMP | %15s:%05d | %15s:%05d |\n",
                 ip_htoa(dev->ip_dev->nat_dev->entries->icmp[i].local_addr),
                 dev->ip_dev->nat_dev->entries->icmp[i].local_port,
                 ip_htoa(dev->ip_dev->nat_dev->entries->icmp[i].global_addr),
                 dev->ip_dev->nat_dev->entries->icmp[i].global_port);
        }
      }
    }
  }
  printf("|-------|-----------------------|-----------------------|\n");
}

/**
 * Perform address translation for NAT.
 * @param ip_packet Packet to perform address translation
 * @param len Remaining length of packet to perform address translation
 * @param nat_dev NAT device
 * @param proto IP protocol type (only UDP, TCP, and ICMP are supported)
 * @param direction NAT direction
 * @return whether NAT succeeded or not.
 */
bool nat_exec(ip_header *ip_packet, size_t len, nat_device *nat_dev,
              nat_protocol proto, nat_direction direction) {
  auto nat_packet =
      (nat_packet_head *)((uint8_t *)ip_packet + sizeof(ip_header));
  if (proto == nat_protocol::icmp and
      nat_packet->icmp.header.type != ICMP_TYPE_ECHO_REQUEST and
      nat_packet->icmp.header.type != ICMP_TYPE_ECHO_REPLY) {
    return false;
  }

  nat_entry *entry;
  if (direction == nat_direction::incoming) {  // Communication from outside NAT
                                               // to inside NAT
    if (proto == nat_protocol::icmp) {
      // Use ID for ICMP
      entry = get_nat_entry_by_global(nat_dev->entries, proto,
                                      ntohl(ip_packet->dest_addr),
                                      ntohs(nat_packet->icmp.identify));
    } else {
      // Use port for TCP/UDP
      entry = get_nat_entry_by_global(nat_dev->entries, proto,
                                      ntohl(ip_packet->dest_addr),
                                      ntohs(nat_packet->dest_port));
    }
    if (entry == nullptr) {
      // Returns false if no NAT entry is registered
      LOG_NAT("Nat entry doesn't exist: global port %d, global address %s\n",
              nat_packet->dest_port, ip_ntoa(ip_packet->dest_addr));
      return false;
    }
  } else {  // Communication from inside NAT to outside NAT
    if (proto == nat_protocol::icmp) {
      // Use ID for ICMP
      entry = get_nat_entry_by_local(nat_dev->entries, proto,
                                     ntohl(ip_packet->src_addr),
                                     ntohs(nat_packet->icmp.identify));
    } else {
      // Use port for TCP/UDP
      entry = get_nat_entry_by_local(nat_dev->entries, proto,
                                     ntohl(ip_packet->src_addr),
                                     ntohs(nat_packet->src_port));
    }
    if (entry == nullptr) {
      entry = create_nat_entry(nat_dev->entries, proto);
      if (entry == nullptr) {
        LOG_NAT("NAT table is full!\n");
        return false;
      }
      LOG_NAT("Created new nat table entry global port %d\n",
              entry->global_port);
      entry->global_addr = nat_dev->outside_addr;
      entry->local_addr = ntohl(ip_packet->src_addr);
      if (proto == nat_protocol::icmp) {
        entry->local_port = ntohs(nat_packet->icmp.identify);
      } else {
        entry->local_port = ntohs(nat_packet->src_port);
      }
      dump_nat_tables();
    }
  }
  int32_t checksum;
  if (proto == nat_protocol::icmp) {
    checksum = nat_packet->icmp.header.checksum;
    checksum = ~checksum;
    checksum -= nat_packet->icmp.identify;
    if (direction == nat_direction::incoming) {
      checksum += htons(entry->local_port);
    } else {
      checksum += htons(entry->global_port);
    }
  } else {
    //
    if (proto == nat_protocol::udp) {  // UDP
      checksum = nat_packet->udp.checksum;
    } else {  // TCP
      checksum = nat_packet->tcp.checksum;
    }
    checksum = ~checksum;

    if (direction == nat_direction::incoming) {
      checksum -= ip_packet->dest_addr & 0xffff;
      checksum -= ip_packet->dest_addr >> 16;
      checksum -= nat_packet->dest_port;
      checksum += htonl(entry->local_addr) & 0xffff;
      checksum += htonl(entry->local_addr) >> 16;
      checksum += htons(entry->local_port);
    } else {
      checksum -= ip_packet->src_addr & 0xffff;
      checksum -= ip_packet->src_addr >> 16;
      checksum -= nat_packet->src_port;
      checksum += htonl(nat_dev->outside_addr) & 0xffff;
      checksum += htonl(nat_dev->outside_addr) >> 16;
      checksum += htons(entry->global_port);
    }
  }
  checksum = ~checksum;

  if (checksum > 0xffff) {
    checksum = (checksum & 0xffff) + (checksum >> 16);
  }

  if (proto == nat_protocol::icmp) {  // ICMP
    nat_packet->icmp.header.checksum = checksum;
  } else if (proto == nat_protocol::udp) {  // UDP
    nat_packet->udp.checksum = checksum;
  } else {  // TCP
    nat_packet->tcp.checksum = checksum;
  }
  if (direction == nat_direction::incoming) {
    ip_packet->dest_addr = htonl(entry->local_addr);
    if (proto == nat_protocol::icmp) {  // ICMP
      nat_packet->icmp.identify = htons(entry->local_port);
    } else {  // UDP/TCP
      nat_packet->dest_port = htons(entry->local_port);
    }
  } else {
    ip_packet->src_addr = htonl(nat_dev->outside_addr);
    if (proto == nat_protocol::icmp) {  // ICMP
      nat_packet->icmp.identify = htons(entry->global_port);
    } else {  // UDP/TCP
      nat_packet->src_port = htons(entry->global_port);
    }
  }

  // Recalcurate the header checksum of ip header
  ip_packet->header_checksum = 0;
  ip_packet->header_checksum =
      checksum_16(reinterpret_cast<uint16_t *>(ip_packet), sizeof(ip_header));
  return true;
}

/**
 * Get NAT entries from global address and global port
 * @param entries
 * @param proto
 * @param addr
 * @param port
 * @return
 */
nat_entry *get_nat_entry_by_global(nat_entries *entries, nat_protocol proto,
                                   uint32_t addr, uint16_t port) {
  if (proto == nat_protocol::udp) {
    if (entries->udp[port - NAT_GLOBAL_PORT_MIN].global_addr == addr and
        entries->udp[port - NAT_GLOBAL_PORT_MIN].global_port == port) {
      return &entries->udp[port - NAT_GLOBAL_PORT_MIN];
    }
  } else if (proto == nat_protocol::tcp) {
    if (entries->tcp[port - NAT_GLOBAL_PORT_MIN].global_addr == addr and
        entries->tcp[port - NAT_GLOBAL_PORT_MIN].global_port == port) {
      return &entries->tcp[port - NAT_GLOBAL_PORT_MIN];
    }
  } else if (proto == nat_protocol::icmp) {
    if (entries->icmp[port].global_addr == addr and
        entries->icmp[port].global_port == port) {
      return &entries->icmp[port];
    }
  }
  return nullptr;
}

/**
 * Get NAT entries from local address and local port
 * @param entries
 * @param proto
 * @param addr
 * @param port
 * @return
 */
nat_entry *get_nat_entry_by_local(nat_entries *entries, nat_protocol proto,
                                  uint32_t addr, uint16_t port) {
  if (proto == nat_protocol::udp) {
    for (int i = 0; i < NAT_GLOBAL_PORT_SIZE; ++i) {
      if (entries->udp[i].local_addr == addr and
          entries->udp[i].local_port == port) {
        return &entries->udp[i];
      }
    }
  } else if (proto == nat_protocol::tcp) {
    for (int i = 0; i < NAT_GLOBAL_PORT_SIZE; ++i) {
      if (entries->tcp[i].local_addr == addr and
          entries->tcp[i].local_port == port) {
        return &entries->tcp[i];
      }
    }
  } else if (proto == nat_protocol::icmp) {
    for (int i = 0; i < NAT_GLOBAL_PORT_SIZE; ++i) {
      if (entries->icmp[i].local_addr == addr and
          entries->icmp[i].local_port == port) {
        return &entries->icmp[i];
      }
    }
  }
  return nullptr;
}

/**
 * Find free ports and create NAT entries
 * @param entries
 * @param proto
 * @return
 */
nat_entry *create_nat_entry(nat_entries *entries, nat_protocol proto) {
  if (proto == nat_protocol::udp) {
    for (int i = 0; i < NAT_GLOBAL_PORT_SIZE; ++i) {
      if (entries->udp[i].global_addr == 0) {
        entries->udp[i].global_port = NAT_GLOBAL_PORT_MIN + i;
        return &entries->udp[i];
      }
    }
  } else if (proto == nat_protocol::tcp) {
    for (int i = 0; i < NAT_GLOBAL_PORT_SIZE; ++i) {
      if (entries->tcp[i].global_addr == 0) {
        entries->tcp[i].global_port = NAT_GLOBAL_PORT_MIN + i;
        return &entries->tcp[i];
      }
    }
  } else if (proto == nat_protocol::icmp) {
    for (int i = 0; i < NAT_GLOBAL_PORT_SIZE; ++i) {
      if (entries->icmp[i].global_addr == 0) {
        entries->icmp[i].global_port = i;
        return &entries->icmp[i];
      }
    }
  }
  return nullptr;
}