#include "config.h"

#include <gtest/gtest.h>

#include "ip.h"
#include "net.h"
#include "utils.h"

class NetworkConfigTest : public ::testing::Test {
 protected:
  void SetUp() override {
    // Initialize net_device object
    netdev = new net_device();
    strcpy(netdev->name, "test_device");
  }

  void TearDown() override {
    // Free memory allocated for net_device object
    free(netdev->ip_dev);
    delete netdev;
  }

  net_device* netdev;
};

TEST_F(NetworkConfigTest, SetIPAddress) {
  uint32_t address = 0xC0A80101;  // 192.168.1.1
  uint32_t netmask = 0xFFFFFF00;  // 255.255.255.0

  // Capture the console output
  testing::internal::CaptureStdout();

  // Call function under test
  configure_ip_address(netdev, address, netmask);

  // Get the console output and check if it matches the expected output
  std::string output = testing::internal::GetCapturedStdout();
  EXPECT_EQ(output, "Set ip address to test_device\n");

  // Check that the ip_device was created and configured correctly
  ASSERT_NE(netdev->ip_dev, nullptr);
  EXPECT_EQ(netdev->ip_dev->address, address);
  EXPECT_EQ(netdev->ip_dev->netmask, netmask);
  EXPECT_EQ(netdev->ip_dev->broadcast, 0xC0A801FF);  // 192.168.1.255
}