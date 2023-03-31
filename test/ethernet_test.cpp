#include "ethernet.h"

#include <gtest/gtest.h>

#include "log.h"
#include "my_buf.h"
#include "net.h"

int mock_device_transmit(net_device *dev, uint8_t *buffer, size_t len) {
  // if (len == ETHER_TYPE_IP) {
  //   LOG_ETHERNET("Sent IP frame.");
  // } else if (len == ETHER_TYPE_ARP) {
  //   LOG_ETHERNET("Sent ARP frame.");
  // }
  LOG_ETHERNET("Mock Device Transmit\n");
  return 0;
}

TEST(EthernetEncapsulateTest, MockTest) {
  auto *dev =
      (net_device *)calloc(1, sizeof(net_device) + sizeof(net_device_data));
  dev->ops.transmit = mock_device_transmit;
  uint8_t source_addr[6] = {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
  memcpy(dev->mac_addr, source_addr, 6);
  my_buf *payload = my_buf::create(sizeof(uint8_t));
  uint8_t dest_addr[6] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66};

  testing::internal::CaptureStdout();
  ethernet_encapsulate_output(dev, dest_addr, payload, ETHER_TYPE_IP);
  std::string output = testing::internal::GetCapturedStdout();
  EXPECT_EQ(
      "[ETHER] Sending ethernet frame type 0800 from aa:bb:cc:dd:ee:ff "
      "to 11:22:33:44:55:66\n"
      "[ETHER] Mock Device Transmit\n",
      output);
}