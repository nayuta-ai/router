#include "interface.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "net.h"

TEST(IsIgnoreInterfaceTest, ValidIgnoreInterface) {
  const char *ifname = "lo";
  bool result = is_ignore_interface(ifname);
  EXPECT_TRUE(result);
}

TEST(IsIgnoreInterfaceTest, InvalidIgnoreInterface) {
  const char *ifname = "eth0";
  bool result = is_ignore_interface(ifname);
  EXPECT_FALSE(result);
}

TEST(NetDeviceTest, GetNetDeviceByName) {
  net_device *eth0 = new net_device;
  strcpy(eth0->name, "eth0");
  eth0->mac_addr[0] = 0x12;
  eth0->mac_addr[1] = 0x34;
  eth0->mac_addr[2] = 0x56;
  eth0->mac_addr[3] = 0x78;
  eth0->mac_addr[4] = 0x9a;
  eth0->mac_addr[5] = 0xbc;
  eth0->ops = {};
  eth0->ip_dev = nullptr;
  eth0->next = nullptr;
  net_device *eth1 = new net_device;
  strcpy(eth1->name, "eth1");
  eth1->mac_addr[0] = 0x12;
  eth1->mac_addr[1] = 0x43;
  eth1->mac_addr[2] = 0x56;
  eth1->mac_addr[3] = 0x78;
  eth1->mac_addr[4] = 0x9a;
  eth1->mac_addr[5] = 0xbc;
  eth1->ops = {};
  eth1->ip_dev = nullptr;
  eth1->next = nullptr;
  net_dev_list = eth0;
  eth0->next = eth1;
  // Test with an existing device name
  net_device *dev = get_net_device_by_name("eth0");
  ASSERT_NE(dev, nullptr);
  EXPECT_STREQ(dev->name, "eth0");

  // Test with a non-existing device name
  dev = get_net_device_by_name("eth2");
  EXPECT_EQ(dev, nullptr);

  // Clean up the linked list of net_device objects
  dev = net_dev_list;
  while (dev) {
    net_device *next = dev->next;
    delete dev;
    dev = next;
  }
  net_dev_list = nullptr;
}
