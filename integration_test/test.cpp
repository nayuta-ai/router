#include <gtest/gtest.h>

#include "device.h"
#include "ethernet.h"
#include "ip.h"
#include "log.h"
#include "net.h"

extern net_device *net_dev_list;

int dummy_transmit(net_device *dev, uint8_t *buffer, size_t len) {
  LOG_ETHERNET("Send dummy packet\n");
  return 0;
}

int dummy_pool(net_device *dev) {
  /**
   * Destination MAC address: 02:42:ac:11:00:02
   *  Source MAC address: 02:42:ac:11:00:03
   * Ethernet Type: ETHER_TYPE_IP(0x0800)
   * header_len = 5, version = 4
   * tos = 0, total_len = 0, identify = 0, frag_offset = 0, ttl = 0
   * Protocol: IP_PROTOCOL_NUM_ICMP(0x01)
   * Header Checksum: 0
   * Source IP address: 192.168.1.2
   * Destination IP address: 192.168.1.1
   */
  uint8_t recv_buffer[] = {0x02, 0x42, 0xac, 0x11, 0x00, 0x02, 0x02, 0x42, 0xac,
                           0x11, 0x00, 0x03, 0x08, 0x00, 0x45, 0x00, 0x00, 0x22,
                           0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0xc0,
                           0xa8, 0x01, 0x02, 0xc0, 0xa8, 0x01, 0x01};
  long unsigned int n = sizeof(ethernet_header) + sizeof(ip_header);
  ethernet_input(dev, recv_buffer, n);
  return 0;
}

void dummy_interface() {
  auto *dev =
      (net_device *)calloc(1, sizeof(net_device) + sizeof(net_device_data));
  dev->ops.transmit = dummy_transmit;
  dev->ops.poll = dummy_pool;
  strcpy(dev->name, "eth0");
  uint8_t mac_addr[] = {0x02, 0x42, 0xac, 0x11, 0x00, 0x02};
  memcpy(dev->mac_addr, mac_addr, 6);
  ((net_device_data *)dev->data)->fd = 4;
  auto *ip_dev = (ip_device *)calloc(1, sizeof(ip_device));
  ip_dev->address = 0xc0a80101;
  ip_dev->netmask = 0xffff0000;
  ip_dev->broadcast = 0xa8c0ffff;
  dev->ip_dev = ip_dev;

  net_device *next;
  next = net_dev_list;
  net_dev_list = dev;
  dev->next = next;
}

class IntegrationTest : public testing::Test {
 protected:
  virtual void SetUp() override {
    prev = net_dev_list;
    net_dev_list = nullptr;
  }
  virtual void TearDown() override { net_dev_list = prev; }

 private:
  net_device *prev;
};

TEST_F(IntegrationTest, RegisterDummyInterface) {
  dummy_interface();
  testing::internal::CaptureStdout();
  for (net_device *dev = net_dev_list; dev; dev = dev->next) {
    dev->ops.poll(dev);
    ASSERT_NE(dev, nullptr);
  }
  std::string output = testing::internal::GetCapturedStdout();

  EXPECT_EQ(
      "[ETHER] Received ethernet frame type 0800 from 02:42:ac:11:00:03 to "
      "02:42:ac:11:00:02\n"
      "[IP] Received IP packet type 1 from 192.168.1.2 to 192.168.1.1\n"
      "[IP] ICMP received!\n",
      output);
}

TEST_F(IntegrationTest, Test) {
  uint8_t dest_addr[6] = {0x02, 0x42, 0xac, 0x11, 0x00, 0x02};
  uint8_t src_addr[6] = {0x02, 0x42, 0xac, 0x11, 0x00, 0x03};
  uint16_t type = ETHER_TYPE_IP;
  auto *eth = (struct ethernet_header *)calloc(1, sizeof(ethernet_header));
  memcpy(eth->dest_addr, dest_addr, 6);
  memcpy(eth->src_addr, src_addr, 6);
  eth->type = type;

  uint8_t *buf = reinterpret_cast<uint8_t *>(eth);
  for (int i = 0; i < sizeof(ethernet_header); ++i) {
    printf("%02x", buf[i]);
  }
  printf("\n");
}