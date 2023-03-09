#include "arp.h"

#include <gtest/gtest.h>

#include "net.h"

class ArpTableTest : public ::testing::Test {
 protected:
  virtual void SetUp() { arp_table_entry arp_table[ARP_TABLE_SIZE]; }

  virtual void TearDown() {}
};

TEST(AddArpTableEntryTest, ValidCase) {
  net_device dev;
  uint8_t mac_addr[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
  uint32_t ip_addr = 0x0a000001;  // 10.0.0.1
  add_arp_table_entry(&dev, mac_addr, ip_addr);

  const uint32_t index = ip_addr % ARP_TABLE_SIZE;
  // Check that the entry was added to the correct location in the ARP table
  EXPECT_EQ(memcmp(arp_table[index].mac_addr, mac_addr, 6), 0);
  EXPECT_EQ(arp_table[index].ip_addr, ip_addr);
  EXPECT_EQ(arp_table[index].dev, &dev);
}

TEST(AddArpTableEntryTest, DuplicateCase) {
  net_device dev1;
  uint8_t mac_addr1[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
  uint32_t ip_addr1 = 0x0a000001;  // 10.0.0.1
  add_arp_table_entry(&dev1, mac_addr1, ip_addr1);

  net_device dev2;
  uint8_t mac_addr2[] = {0x11, 0x12, 0x13, 0x14, 0x15, 0x16};
  uint32_t ip_addr2 = 0x0a000002;  // 10.0.0.2
  add_arp_table_entry(&dev2, mac_addr2, ip_addr2);

  net_device dev3;
  uint8_t mac_addr3[] = {0x21, 0x22, 0x23, 0x24, 0x25, 0x26};
  uint32_t ip_addr3 = 0x0a000003;  // 10.0.0.3
  add_arp_table_entry(&dev3, mac_addr3, ip_addr3);

  int cnt = 0;
  for (int i = 0; i < ARP_TABLE_SIZE; i++) {
    if (arp_table[i].ip_addr == ip_addr1) {
      EXPECT_EQ(memcmp(arp_table[i].mac_addr, mac_addr1, 6), 0);
      cnt++;
    }
    if (arp_table[i].ip_addr == ip_addr2) {
      EXPECT_EQ(memcmp(arp_table[i].mac_addr, mac_addr2, 6), 0);
      cnt++;
    }
    if (arp_table[i].ip_addr == ip_addr3) {
      EXPECT_EQ(memcmp(arp_table[i].mac_addr, mac_addr3, 6), 0);
      cnt++;
    }
  }
  EXPECT_EQ(cnt, 3);
}