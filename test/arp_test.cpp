#include "arp.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "ethernet.h"
#include "ip.h"
#include "log.h"
#include "my_buf.h"
#include "net.h"
#include "utils.h"

// Declare the external array in the test file
extern arp_table_entry arp_table[ARP_TABLE_SIZE];

// Define the test fixture
class ArpTableTest : public ::testing::Test {
 protected:
  // Initialize the arp_table array before each test
  virtual void SetUp() {}

  // Tear down the arp_table array after each test
  virtual void TearDown() {
    // Reset the arp_table to its initial state
    arp_table_entry default_entry = {};
    for (int i = 0; i < ARP_TABLE_SIZE; ++i) {
      arp_table[i] = default_entry;
    }
  }
};

TEST_F(ArpTableTest, AddValidCase) {
  net_device dev;
  uint8_t mac_addr[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
  uint32_t ip_addr = 0x0a000001;  // 10.0.0.1
  const uint32_t index = ip_addr % ARP_TABLE_SIZE;

  add_arp_table_entry(&dev, mac_addr, ip_addr);

  // Check that the entry was added to the correct location in the ARP table
  EXPECT_EQ(memcmp(arp_table[index].mac_addr, mac_addr, 6), 0);
  EXPECT_EQ(arp_table[index].ip_addr, ip_addr);
  EXPECT_EQ(arp_table[index].dev, &dev);
}

TEST_F(ArpTableTest, AddDuplicateCase) {
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

TEST_F(ArpTableTest, SearchValidCase) {
  net_device dev;
  arp_table_entry *arp;
  uint8_t mac_addr[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
  uint32_t ip_addr = 0x0a000001;  // 10.0.0.1
  add_arp_table_entry(&dev, mac_addr, ip_addr);

  arp = search_arp_table_entry(ip_addr);

  EXPECT_EQ(ip_addr, arp->ip_addr);
  EXPECT_EQ(0, memcmp(arp->mac_addr, mac_addr, 6));
}

TEST_F(ArpTableTest, SearchNullCase) {
  arp_table_entry *arp;
  uint32_t ip_addr = 0x0a000001;  // 10.0.0.1

  arp = search_arp_table_entry(ip_addr);

  EXPECT_EQ(nullptr, arp);
}

TEST_F(ArpTableTest, DumpValidCase) {
  net_device dev;
  strcpy(dev.name, "dev");
  arp_table_entry *arp;
  uint8_t mac_addr[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
  uint32_t ip_addr = 0x0a000001;  // 10.0.0.1
  add_arp_table_entry(&dev, mac_addr, ip_addr);

  testing::internal::CaptureStdout();
  dump_arp_table_entry();
  std::string output = testing::internal::GetCapturedStdout();

  EXPECT_EQ(
      "|---IP ADDRESS----|----MAC ADDRESS----|------DEVICE-------|-INDEX-|\n"
      "|        10.0.0.1 | 01:02:03:04:05:06 |               dev |  0051 |\n"
      "|-----------------|-------------------|-------------------|-------|"
      "\n",
      output);
}

TEST_F(ArpTableTest, ReplyArrivesTest) {
  auto *dev =
      (net_device *)calloc(1, sizeof(net_device) + sizeof(net_device_data));
  uint8_t buffer[sizeof(arp_ip_to_ethernet)] = {0};
  auto *eth = reinterpret_cast<arp_ip_to_ethernet *>(buffer);
  arp_table_entry *arp;
  ip_device ip_dev = {0x0302010a, 0, 0};
  strcpy(dev->name, "dev");
  dev->ip_dev = &ip_dev;
  uint32_t ip_addr = 0x0101a8c0;
  uint8_t sha[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
  memccpy(eth->sha, sha, '\0', ETHERNET_ADDRESS_LEN);
  eth->spa = ip_addr;

  arp_reply_arrives(dev, eth);

  // Check that the entry was added to the correct location in the ARP table
  arp = search_arp_table_entry(ntohl(ip_addr));
  EXPECT_TRUE(arp != nullptr);
  EXPECT_EQ(ntohl(ip_addr), arp->ip_addr);
  EXPECT_EQ(0, memcmp(arp->mac_addr, sha, 6));
}

void ethernet_encapsulate_output(net_device *dev, const uint8_t *dest_addr,
                                 my_buf *payload_mybuf, uint16_t ether_type);

class MockEthernet {
 public:
  MOCK_METHOD(void, ethernet_encapsulate_output,
              (net_device * dev, const uint8_t *dest_addr,
               my_buf *payload_mybuf, uint16_t ether_type));
} *mocketh;

void ethernet_encapsulate_output(net_device *dev, const uint8_t *dest_addr,
                                 my_buf *payload_mybuf, uint16_t ether_type) {
  mocketh->ethernet_encapsulate_output(dev, dest_addr, payload_mybuf,
                                       ether_type);
}

class MockArpTest : public ArpTableTest {
 protected:
  void SetUp() override { mocketh = new MockEthernet(); }

  void TearDown() override { delete mocketh; }
};

using ::testing::_;
using ::testing::Invoke;

TEST_F(MockArpTest, Request) {
  auto *dev =
      (net_device *)calloc(1, sizeof(net_device) + sizeof(net_device_data));
  uint8_t buffer[sizeof(arp_ip_to_ethernet)] = {0};
  auto *eth = reinterpret_cast<arp_ip_to_ethernet *>(buffer);
  arp_table_entry *arp;
  ip_device ip_dev = {0xc0a80101, 0, 0};
  strcpy(dev->name, "dev");
  dev->ip_dev = &ip_dev;
  uint32_t target_addr = 0x0101a8c0;
  uint32_t source_addr = 0x0201a8c0;
  uint8_t tha[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
  uint8_t sha[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x07};
  memccpy(eth->tha, tha, '\0', ETHERNET_ADDRESS_LEN);
  memccpy(eth->sha, sha, '\0', ETHERNET_ADDRESS_LEN);
  eth->tpa = target_addr;
  eth->spa = source_addr;
  my_buf *mybuf = my_buf::create(ETHERNET_ADDRESS_LEN);
  EXPECT_EQ(dev->ip_dev->address, ntohl(eth->tpa));

  // expect send function to be called with correct arguments
  EXPECT_CALL(*mocketh, ethernet_encapsulate_output(_, _, _, _));

  // call the function under test
  arp_request_arrives(dev, eth);

  arp = search_arp_table_entry(ntohl(source_addr));
  EXPECT_TRUE(arp != nullptr);
  EXPECT_EQ(ntohl(source_addr), arp->ip_addr);
  EXPECT_EQ(0, memcmp(arp->mac_addr, sha, 6));
}

TEST_F(MockArpTest, Send) {
  auto *dev =
      (net_device *)calloc(1, sizeof(net_device) + sizeof(net_device_data));
  uint8_t mac_addr[] = {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
  strcpy(dev->name, "dev");
  memcpy(dev->mac_addr, mac_addr, 6);
  ip_device ip_dev = {0x0302010a, 0, 0};
  dev->ip_dev = &ip_dev;
  uint32_t ip_addr = 0x0a000001;

  // expect send function to be called with correct arguments
  EXPECT_CALL(*mocketh, ethernet_encapsulate_output(_, _, _, _));

  testing::internal::CaptureStdout();
  send_arp_request(dev, ip_addr);
  std::string output = testing::internal::GetCapturedStdout();

  EXPECT_EQ("[ARP] Sending arp request via dev for 10.0.0.1\n", output);
}