#include "icmp.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "ip.h"
#include "log.h"
#include "my_buf.h"
#include "net.h"
#include "utils.h"

void ip_encapsulate_output(uint32_t dest_addr, uint32_t src_addr,
                           my_buf *payload_mybuf, uint8_t protocol_num);

class MockIP {
 public:
  MOCK_METHOD(void, ip_encapsulate_output,
              (uint32_t dest_addr, uint32_t src_addr, my_buf *payload_mybuf,
               uint8_t protocol_num));
} *mockip;

void ip_encapsulate_output(uint32_t dest_addr, uint32_t src_addr,
                           my_buf *payload_mybuf, uint8_t protocol_num) {
  mockip->ip_encapsulate_output(dest_addr, src_addr, payload_mybuf,
                                protocol_num);
}

class MockICMPTest : public ::testing::Test {
 protected:
  void SetUp() override { mockip = new MockIP(); }

  void TearDown() override { delete mockip; }
};

using ::testing::_;

TEST_F(MockICMPTest, SendICMPDestinationUnreachableTest) {
  uint32_t source = 0xc0a80002;
  uint32_t destination = 0xc0a80003;
  my_buf *unreachable_mybuf = my_buf::create(sizeof(ip_header) + 10);

  // expect send function to be called with correct arguments
  EXPECT_CALL(*mockip, ip_encapsulate_output(_, _, _, _));

  testing::internal::CaptureStdout();
  send_icmp_destination_unreachable(
      source, destination, ICMP_DESTINATION_UNREACHABLE_CODE_PORT_UNREACHABLE,
      unreachable_mybuf, sizeof(ip_header) + 10);
  std::string output = testing::internal::GetCapturedStdout();

  EXPECT_EQ("", output);
}

class InputICMP : public MockICMPTest {};

TEST_F(InputICMP, EchoReplyTest) {
  uint32_t source = 0xc0a80002;
  uint32_t destination = 0xc0a80003;
  auto *reply_msg = (icmp_message *)malloc(sizeof(icmp_message));
  reply_msg->header.type = ICMP_TYPE_ECHO_REPLY;
  reply_msg->header.code = 0;
  reply_msg->header.checksum = 0;
  reply_msg->echo.identify = 0x1234;
  reply_msg->echo.sequence = 0x5678;
  void *buffer = reply_msg;
  size_t len = sizeof(reply_msg);
  char expected[100];
  sprintf(expected, "[ICMP] Received icmp echo reply id %04x seq %d\n",
          ntohs(reply_msg->echo.identify), ntohs(reply_msg->echo.sequence));

  testing::internal::CaptureStdout();
  icmp_input(source, destination, buffer, len);
  std::string output = testing::internal::GetCapturedStdout();

  EXPECT_EQ(expected, output);

  free(reply_msg);
}

TEST_F(InputICMP, EchoRequestTest) {
  uint32_t source = 0xc0a80002;
  uint32_t destination = 0xc0a80003;
  auto *request_msg = (icmp_message *)malloc(sizeof(icmp_message));
  request_msg->header.type = ICMP_TYPE_ECHO_REQUEST;
  request_msg->header.code = 0;
  request_msg->header.checksum = 0;
  request_msg->echo.identify = 0x1234;
  request_msg->echo.sequence = 0x5678;
  const char *data = "Test data";
  memcpy(request_msg->echo.data, data, strlen(data) + 1);
  void *buffer = request_msg;
  size_t len = sizeof(request_msg);
  // Expected Output
  char expected[100];
  sprintf(expected, "[ICMP] Received icmp echo request id %04x seq %d\n",
          ntohs(request_msg->echo.identify), ntohs(request_msg->echo.sequence));

  // expect send function to be called with correct arguments
  EXPECT_CALL(*mockip, ip_encapsulate_output(_, _, _, _));

  testing::internal::CaptureStdout();
  icmp_input(source, destination, buffer, len);
  std::string output = testing::internal::GetCapturedStdout();

  EXPECT_EQ(expected, output);

  free(request_msg);
}

TEST_F(InputICMP, UnknownType) {
  uint32_t source = 0xc0a80002;
  uint32_t destination = 0xc0a80003;
  auto *msg = (icmp_message *)malloc(sizeof(icmp_message));
  msg->header.type =
      ICMP_TYPE_DESTINATION_UNREACHABLE;  // Not ICMP_TYPE_ECHO_REPLY and
                                          // ICMP_TYPE_ECHO_REQUEST
  void *buffer = msg;
  size_t len = sizeof(msg);
  // Expected Output
  char expected[100];
  sprintf(expected, "[ICMP] Received unhandled icmp type %d\n",
          msg->header.type);

  testing::internal::CaptureStdout();
  icmp_input(source, destination, buffer, len);
  std::string output = testing::internal::GetCapturedStdout();

  EXPECT_EQ(expected, output);

  free(msg);
}