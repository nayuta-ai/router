#include "ip.h"

#include <gtest/gtest.h>
#include <netinet/in.h>

#include "net.h"

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

TEST(IPInputTest, TCP) {
  // Set up input data (a network device without IP address)
  net_device input_dev;
  input_dev.ip_dev = nullptr;
  strcpy(input_dev.name, "eth0");

  // Set up input data (a buffer containing an IP packet)
  uint8_t buffer[sizeof(ip_header)] = {0};
  auto *ip_packet = reinterpret_cast<ip_header *>(buffer);
  ip_packet->version = 4;
  ip_packet->header_len = sizeof(ip_header) >> 2;
  ip_packet->src_addr = 0x0a010101;   // 10.1.1.1
  ip_packet->dest_addr = 0x0a010102;  // 10.1.1.2
  ip_packet->protocol = IPPROTO_TCP;

  // Call the function and check the result (no output or side effect expected)
  ip_input(&input_dev, buffer, sizeof(ip_header));
  // No assertion required, the test case will pass if the function returns
  // normally
}