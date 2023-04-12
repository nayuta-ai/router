#include "ip.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <netinet/in.h>

#include "arp.h"
#include "device.h"
#include "log.h"
#include "my_buf.h"
#include "net.h"
#include "utils.h"

TEST(SubnetTest, InSubnetTest) {
  uint32_t subnet_prefix = 0xc0a80000;  // 192.168.0.0
  uint32_t subnet_mask = 0xffffff00;    // 255.255.255.0

  // Test an address in the subnet
  uint32_t in_subnet_address = 0xc0a80001;  // 192.168.0.1
  EXPECT_TRUE(in_subnet(subnet_prefix, subnet_mask, in_subnet_address));

  // Test an address outside the subnet
  uint32_t out_of_subnet_address = 0xc0a80101;  // 192.168.1.1
  EXPECT_FALSE(in_subnet(subnet_prefix, subnet_mask, out_of_subnet_address));
}

// TEST(IPInputTest, TCP) {
//   // Set up input data (a network device without IP address)
//   net_device input_dev;
//   input_dev.ip_dev = nullptr;
//   strcpy(input_dev.name, "eth0");

//   // Set up input data (a buffer containing an IP packet)
//   uint8_t buffer[sizeof(ip_header)] = {0};
//   auto *ip_packet = reinterpret_cast<ip_header *>(buffer);
//   ip_packet->version = 4;
//   ip_packet->header_len = sizeof(ip_header) >> 2;
//   ip_packet->src_addr = 0x0a010101;   // 10.1.1.1
//   ip_packet->dest_addr = 0x0a010102;  // 10.1.1.2
//   ip_packet->protocol = IPPROTO_TCP;

//   // Call the function and check the result (no output or side effect
//   expected) ip_input(&input_dev, buffer, sizeof(ip_header));
//   // No assertion required, the test case will pass if the function returns
//   // normally
// }

extern net_device *net_dev_list;

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

class MockIPTest : public ::testing::Test {
 protected:
  void SetUp() override { mocketh = new MockEthernet(); }

  void TearDown() override {
    delete mocketh;
    // Reset the arp_table to its initial state
    arp_table_entry default_entry = {};
    for (int i = 0; i < ARP_TABLE_SIZE; ++i) {
      arp_table[i] = default_entry;
    }
    net_dev_list->next = nullptr;
  }
};

using ::testing::_;

TEST_F(MockIPTest, ExistArpEntry) {
  // Create net_device structure
  auto *dev =
      (net_device *)calloc(1, sizeof(net_device) + sizeof(net_device_data));
  strcpy(dev->name, "dev");
  uint8_t mac_addr[] = {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
  memcpy(dev->mac_addr, mac_addr, 6);
  ip_device ip_dev = {0xc0a80001, 0xc0a80000, 0};
  dev->ip_dev = &ip_dev;
  // Register dev to net_dev_list
  net_device *next;
  next = net_dev_list;
  net_dev_list = dev;
  dev->next = next;
  // Other Setup
  uint32_t source = 0xc0a80002;
  uint32_t destination = 0xc0a80003;
  my_buf *payload = my_buf::create(0);
  add_arp_table_entry(dev, mac_addr, source);

  // expect send function to be called with correct arguments
  EXPECT_CALL(*mocketh, ethernet_encapsulate_output(_, _, _, _));

  testing::internal::CaptureStdout();
  ip_encapsulate_output(source, destination, payload, IP_PROTOCOL_NUM_ICMP);
  std::string output = testing::internal::GetCapturedStdout();

  EXPECT_EQ("", output);
}

TEST_F(MockIPTest, NotExistArpEntry) {
  // Create net_device structure
  auto *dev =
      (net_device *)calloc(1, sizeof(net_device) + sizeof(net_device_data));
  strcpy(dev->name, "dev");
  uint8_t mac_addr[] = {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
  memcpy(dev->mac_addr, mac_addr, 6);
  ip_device ip_dev = {0xc0a80001, 0xc0a80000, 0};
  dev->ip_dev = &ip_dev;
  // Register dev to net_dev_list
  net_device *next;
  next = net_dev_list;
  net_dev_list = dev;
  dev->next = next;
  // Other Setup
  uint32_t source = 0xc0a80002;
  uint32_t destination = 0xc0a80003;
  my_buf *payload = my_buf::create(0);

  // expect send function to be called with correct arguments
  EXPECT_CALL(*mocketh, ethernet_encapsulate_output(_, _, _, _));

  testing::internal::CaptureStdout();
  ip_encapsulate_output(source, destination, payload, IP_PROTOCOL_NUM_ICMP);
  std::string output = testing::internal::GetCapturedStdout();

  EXPECT_EQ(
      "[IP] Trying ip output, but no arp record to 192.168.0.2\n[ARP] Sending"
      " arp request via dev for 192.168.0.2\n",
      output);
}

// void icmp_input(uint32_t source, uint32_t destination, void *buffer,
//                 size_t len);

// void send_icmp_destination_unreachable(uint32_t dest_addr, uint32_t src_addr,
//                                        uint8_t code, void *error_ip_buffer,
//                                        size_t len);

// class MockICMP {
//  public:
//   MOCK_METHOD(void, icmp_input,
//               (uint32_t source, uint32_t destination, void *buffer,
//                size_t len));
//   MOCK_METHOD(void, send_icmp_destination_unreachable,
//               (uint32_t dest_addr, uint32_t src_addr, uint8_t code,
//                void *error_ip_buffer, size_t len));
// } *mockicmp;

// void icmp_input(uint32_t source, uint32_t destination, void *buffer,
//                 size_t len) {
//   mockicmp->icmp_input(source, destination, buffer, len);
// }

// void send_icmp_destination_unreachable(uint32_t dest_addr, uint32_t src_addr,
//                                        uint8_t code, void *error_ip_buffer,
//                                        size_t len) {
//   mockicmp->send_icmp_destination_unreachable(dest_addr, src_addr, code,
//                                               error_ip_buffer, len);
// }

// class MockICMPTest : public ::testing::Test {
//  protected:
//   void SetUp() override { mockicmp = new MockICMP(); }

//   void TearDown() override {
//     delete mockicmp;
//     net_dev_list->next = nullptr;
//   }
// };

// TEST_F(MockICMPTest, ICMP) {
//   // Set up input data (a network device without IP address)
//   auto *input_dev = (net_device *)calloc(1, sizeof(net_device) + 1);
//   auto *ip_dev = (ip_device *)calloc(1, sizeof(ip_device) + 1);
//   ip_dev->address = 0x0a010102;
//   ip_dev->netmask = 0;
//   ip_dev->broadcast = 0;
//   input_dev->ip_dev = ip_dev;
//   strcpy(input_dev->name, "eth0");
//   net_device *next;
//   next = net_dev_list;
//   net_dev_list = input_dev;
//   input_dev->next = next;

//   // Set up input data (a buffer containing an IP packet)
//   auto *ip_packet = (ip_header *)malloc(sizeof(ip_header));
//   ip_packet->version = 4;
//   ip_packet->header_len = sizeof(ip_header) >> 2;
//   ip_packet->src_addr = 0x0101010a;   // 10.1.1.1
//   ip_packet->dest_addr = 0x0201010a;  // 10.1.1.2
//   ip_packet->protocol = IP_PROTOCOL_NUM_ICMP;
//   auto *buffer = reinterpret_cast<uint8_t *>(ip_packet);
//   char expected[100];
//   sprintf(expected, "[IP] Received IP packet type %d from %s to %s\n",
//           ip_packet->protocol, ip_ntoa(ip_packet->src_addr),
//           ip_ntoa(ip_packet->dest_addr));

//   EXPECT_CALL(*mockicmp, icmp_input(_, _, _, _));

//   testing::internal::CaptureStdout();
//   // Call the function and check the result (no output or side
//   effectexpected) ip_input(input_dev, buffer, sizeof(ip_header)); std::string
//   output = testing::internal::GetCapturedStdout();

//   EXPECT_EQ(expected, output);
// }

// TEST_F(MockICMPTest, DestinationUnreachable) {
//   // Set up input data (a network device without IP address)
//   auto *input_dev = (net_device *)calloc(1, sizeof(net_device) + 1);
//   auto *ip_dev = (ip_device *)calloc(1, sizeof(ip_device) + 1);
//   ip_dev->address = 0x0a010102;
//   ip_dev->netmask = 0;
//   ip_dev->broadcast = 0;
//   input_dev->ip_dev = ip_dev;
//   strcpy(input_dev->name, "eth0");
//   net_device *next;
//   next = net_dev_list;
//   net_dev_list = input_dev;
//   input_dev->next = next;

//   // Set up input data (a buffer containing an IP packet)
//   auto *ip_packet = (ip_header *)malloc(sizeof(ip_header));
//   ip_packet->version = 4;
//   ip_packet->header_len = sizeof(ip_header) >> 2;
//   ip_packet->src_addr = 0x0101010a;   // 10.1.1.1
//   ip_packet->dest_addr = 0x0201010a;  // 10.1.1.2
//   ip_packet->protocol = IP_PROTOCOL_NUM_UDP;
//   auto *buffer = reinterpret_cast<uint8_t *>(ip_packet);
//   char expected[100];
//   sprintf(expected, "[IP] Received IP packet type %d from %s to %s\n",
//           ip_packet->protocol, ip_ntoa(ip_packet->src_addr),
//           ip_ntoa(ip_packet->dest_addr));

//   EXPECT_CALL(*mockicmp, send_icmp_destination_unreachable(_, _, _, _, _));

//   testing::internal::CaptureStdout();
//   // Call the function and check the result (no output or side
//   effectexpected) ip_input(input_dev, buffer, sizeof(ip_header)); std::string
//   output = testing::internal::GetCapturedStdout();

//   EXPECT_EQ(expected, output);
// }

// TEST_F(MockICMPTest, BroadCast) {
//   // Set up input data (a network device without IP address)
//   auto *input_dev = (net_device *)calloc(1, sizeof(net_device) + 1);
//   auto *ip_dev = (ip_device *)calloc(1, sizeof(ip_device) + 1);
//   ip_dev->address = 0x0a010102;
//   ip_dev->netmask = 0;
//   ip_dev->broadcast = 0;
//   input_dev->ip_dev = ip_dev;
//   strcpy(input_dev->name, "eth0");

//   // Set up input data (a buffer containing an IP packet)
//   auto *ip_packet = (ip_header *)malloc(sizeof(ip_header));
//   ip_packet->version = 4;
//   ip_packet->header_len = sizeof(ip_header) >> 2;
//   ip_packet->src_addr = 0x0101010a;   // 10.1.1.1
//   ip_packet->dest_addr = 0xffffffff;  // 255.255.255.255
//   ip_packet->protocol = IP_PROTOCOL_NUM_ICMP;
//   auto *buffer = reinterpret_cast<uint8_t *>(ip_packet);
//   char expected[100];
//   sprintf(expected, "[IP] Received IP packet type %d from %s to %s\n",
//           ip_packet->protocol, ip_ntoa(ip_packet->src_addr),
//           ip_ntoa(ip_packet->dest_addr));

//   EXPECT_CALL(*mockicmp, icmp_input(_, _, _, _));

//   testing::internal::CaptureStdout();
//   // Call the function and check the result (no output or side
//   effectexpected) ip_input(input_dev, buffer, sizeof(ip_header)); std::string
//   output = testing::internal::GetCapturedStdout();

//   EXPECT_EQ(expected, output);
// }

// TEST_F(MockICMPTest, LOG) {
//   // Set up input data (a network device without IP address)
//   net_device input_dev;
//   input_dev.ip_dev = nullptr;
//   strcpy(input_dev.name, "eth0");
//   // Set up input data (a buffer containing an IP packet)
//   uint8_t buffer[sizeof(ip_header)] = {0};
//   auto *ip_packet = reinterpret_cast<ip_header *>(buffer);
//   ip_packet->protocol = IP_PROTOCOL_NUM_ICMP;

//   EXPECT_CALL(*mockicmp, icmp_input(_, _, _, _));

//   testing::internal::CaptureStdout();
//   ip_input_to_ours(&input_dev, ip_packet, sizeof(ip_header));
//   std::string output = testing::internal::GetCapturedStdout();
//   EXPECT_EQ("", output);
// }