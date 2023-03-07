#include "utils.h"

#include <gtest/gtest.h>

TEST(NtohsTest, ValidTestCase) {
  uint16_t v = 0x1234;
  uint16_t result = ntohs(v);
  EXPECT_EQ(result, 0x3412);
}

TEST(NtohlTest, ValidTestCase) {
  uint32_t v = 0x12345678;
  uint32_t result = ntohl(v);
  EXPECT_EQ(result, 0x78563412);
}

TEST(Htons, ValidTestCase) {
  uint16_t v = 0x3412;
  uint16_t result = htons(v);
  EXPECT_EQ(result, 0x1234);
}

TEST(HtonlTest, ValidTestCase) {
  uint32_t v = 0x78563412;
  uint32_t result = ntohl(v);
  EXPECT_EQ(result, 0x12345678);
}

TEST(MacAddrToaTest, ConvertsMacAddrToString) {
  uint8_t mac_addr[] = {0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC};
  const char* result_string = mac_addr_toa(mac_addr);
  ASSERT_STREQ(result_string, "12:34:56:78:9a:bc");
}

TEST(IPNtoaTest, ConvertsIpAddressToString) {
  // Test 1: Valid input
  uint32_t ip = 0x0302010a;  // 3.2.1.10
  EXPECT_STREQ("10.1.2.3", ip_ntoa(ip));

  // Test 2: Another valid input
  ip = 0x0101a8c0;  // 1.1.168.192
  EXPECT_STREQ("192.168.1.1", ip_ntoa(ip));

  // Test 3: Invalid input (0xffffffff)
  ip = 0xffffffff;
  EXPECT_STREQ("255.255.255.255", ip_ntoa(ip));
}

TEST(IPHtoaTest, ConvertsIpAddressToString) {
  // Test 1: Valid input
  uint32_t ip = 0x0302010a;  // 3.2.1.10
  EXPECT_STREQ("3.2.1.10", ip_htoa(ip));

  // Test 2: Another valid input
  ip = 0x0101a8c0;  // 1.1.168.192
  EXPECT_STREQ("1.1.168.192", ip_htoa(ip));

  // Test 3: Invalid input (0xffffffff)
  ip = 0xffffffff;
  EXPECT_STREQ("255.255.255.255", ip_htoa(ip));
}

TEST(ChecksumTest, BasicChecksumTest) {
  // Set up input data (a buffer of 4 bytes)
  uint16_t buffer[2] = {0x1234, 0x5678};

  // Call the function and check the result
  uint16_t checksum = checksum_16(buffer, 4, 0);
  EXPECT_EQ(checksum, 0x9753);

  // Set up input data (a buffer of 5 bytes)
  uint16_t buffer2[3] = {0x1234};

  // Call the function and check the result
  checksum = checksum_16(buffer2, 2, 0);
  EXPECT_EQ(checksum, 0xedcb);
}
