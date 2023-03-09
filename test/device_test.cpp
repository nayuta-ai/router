#include "device.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <sys/socket.h>

#include "net.h"

ssize_t send(int sockfd, const void *buf, size_t len, int flags);

class MockSocket {
 public:
  MOCK_METHOD4(send,
               ssize_t(int sockfd, const void *buf, size_t len, int flags));
} *mockSocket;

ssize_t send(int sockfd, const void *buf, size_t len, int flags) {
  return mockSocket->send(sockfd, &buf, len, flags);
}

class NetDeviceTest : public testing::Test {
 protected:
  net_device_data *dev_data;
  net_device dev;

  void SetUp() override {
    mockSocket = new MockSocket();
    // allocate memory for the device data
    auto *dev =
        (net_device *)calloc(1, sizeof(net_device) + sizeof(net_device_data));

    // set up the device and device data
    dev_data = (net_device_data *)dev->data;
    dev_data->fd = 123;
  }

  void TearDown() override { delete mockSocket; }
};

using ::testing::_;
using ::testing::Return;

TEST_F(NetDeviceTest, Transmit) {
  uint8_t buffer[] = {1, 2, 3};
  size_t len = sizeof(buffer);

  // expect send function to be called with correct arguments
  EXPECT_CALL(*mockSocket, send(_, _, _, _)).WillOnce(testing::Return(len));

  // call the function under test
  int result = net_device_transmit(&dev, buffer, len);

  // assert that the result is 0
  EXPECT_EQ(result, 0);
}