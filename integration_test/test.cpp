#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "device.h"
#include "log.h"
#include "net.h"

extern net_device *net_dev_list;

int dummy_transmit(net_device *dev, uint8_t *buffer, size_t len) {
  LOG_ETHERNET("Send dummy packet\n");
  return 0;
}

int dummy_pool(net_device *dev) {
  uint8_t recv_buffer[] = {
      0x33, 0x33, 0x00, 0x00, 0x00, 0x02, 0x96, 0xbc, 0x2b, 0xa3, 0xa3, 0xa9,
      0x86, 0xdd, 0x60, 0x00, 0x00, 0x00, 0x00, 0x10, 0x3a, 0xff, 0xfe, 0x80,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x94, 0xbc, 0x2b, 0xff, 0xfe, 0xa3,
      0xa3, 0xa9, 0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x85, 0x00, 0xb3, 0x1b, 0x00, 0x00,
      0x00, 0x00, 0x01, 0x01, 0x96, 0xbc, 0x2b, 0xa3, 0xa3, 0xa9,
  };
  long unsigned int n = 70;
  printf("Received %lu bytes from %s: ", n, dev->name);
  for (int i = 0; i < n; ++i) {
    printf("%02x", recv_buffer[i]);
  }
  printf("\n");
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
  for (net_device *dev = net_dev_list; dev; dev = dev->next) {
    dev->ops.poll(dev);
    ASSERT_NE(dev, nullptr);
  }
}