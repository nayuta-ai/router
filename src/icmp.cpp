#include "icmp.h"

#include <cstring>

#include "config.h"
#include "ip.h"
#include "log.h"
#include "my_buf.h"
#include "net.h"
#include "utils.h"

/**
 * Receiving and processing ICMP packets
 * @param source
 * @param destination
 * @param buffer
 * @param len
 */
void icmp_input(uint32_t source, uint32_t destination, void *buffer,
                size_t len) {
  // If shorter than the ICMP message length
  if (len < sizeof(icmp_header)) {
    LOG_ICMP("Received ICMP packet too short\n");
    return;
  }
  // Interpreted as ICMP packets
  auto *icmp_msg = reinterpret_cast<icmp_message *>(buffer);
  switch (icmp_msg->header.type) {
    case ICMP_TYPE_ECHO_REPLY:
      // If shorter than the minimum length of ICMP Echo
      if (len < sizeof(icmp_header) + sizeof(icmp_echo)) {
        LOG_ICMP("Received ICMP echo packet too short\n");
        return;
      }
      LOG_ICMP("Received icmp echo reply id %04x seq %d\n",
               ntohs(icmp_msg->echo.identify), ntohs(icmp_msg->echo.sequence));
      break;
    case ICMP_TYPE_ECHO_REQUEST: {
      // If shorter than the minimum length of ICMP Echo
      if (len < sizeof(icmp_header) + sizeof(icmp_echo)) {
        LOG_ICMP("Received ICMP echo packet too short\n");
        return;
      }

      LOG_ICMP("Received icmp echo request id %04x seq %d\n",
               ntohs(icmp_msg->echo.identify), ntohs(icmp_msg->echo.sequence));

      my_buf *reply_mybuf = my_buf::create(len);

      auto *reply_msg = reinterpret_cast<icmp_message *>(reply_mybuf->buffer);
      reply_msg->header.type = ICMP_TYPE_ECHO_REPLY;
      reply_msg->header.code = 0;
      reply_msg->header.checksum = 0;
      reply_msg->echo.identify =
          icmp_msg->echo.identify;  // copy the identify number
      reply_msg->echo.sequence =
          icmp_msg->echo.sequence;  // copy the sequence number
      memcpy(&reply_msg->echo.data, &icmp_msg->echo.data,
             len - (sizeof(icmp_header) + sizeof(icmp_echo)));  // copy the data
      reply_msg->header.checksum =
          checksum_16(reinterpret_cast<uint16_t *>(reply_mybuf->buffer),
                      reply_mybuf->len);  // calcuration of checksum

      ip_encapsulate_output(source, destination, reply_mybuf,
                            IP_PROTOCOL_NUM_ICMP);
    } break;

    default:
      LOG_ICMP("Received unhandled icmp type %d\n", icmp_msg->header.type);
      break;
  }
}

/**
 * Send ICMP Time exceeded message
 * @param dest_addr
 * @param src_addr
 * @param code
 * @param error_ip_buffer Packets with errors
 * @param len Length of packets that resulted in an error
 */
void send_icmp_time_exceeded(uint32_t dest_addr, uint32_t src_addr,
                             uint8_t code, void *error_ip_buffer, size_t len) {
  if (len < sizeof(ip_header) + 8) {  // If error packet is too small
    return;
  }

  // Allocate ICMP header + area of message + error packet section (IP header +
  // bytes)
  my_buf *time_exceeded_mybuf = my_buf::create(
      sizeof(icmp_header) + sizeof(icmp_time_exceeded) + sizeof(ip_header) + 8);
  auto *time_exceeded_msg =
      reinterpret_cast<icmp_message *>(time_exceeded_mybuf->buffer);

  // Set each field
  time_exceeded_msg->header.type = ICMP_TYPE_TIME_EXCEEDED;
  time_exceeded_msg->header.code = code;
  time_exceeded_msg->header.checksum = 0;
  time_exceeded_msg->time_exceeded.unused = 0;
  memcpy(time_exceeded_msg->time_exceeded.data, error_ip_buffer,
         sizeof(ip_header) + 8);
  time_exceeded_msg->header.checksum =
      checksum_16(reinterpret_cast<uint16_t *>(time_exceeded_mybuf->buffer),
                  time_exceeded_mybuf->len);

  // Send by IP
  ip_encapsulate_output(dest_addr, src_addr, time_exceeded_mybuf,
                        IP_PROTOCOL_NUM_ICMP);
}

/**
 * Send ICMP Destination unreachable message
 * @param dest_addr
 * @param src_addr
 * @param code Destination unreachable code
 * @param error_ip_buffer Packets with errors
 * @param len Length of packets that resulted in an error
 */
void send_icmp_destination_unreachable(uint32_t dest_addr, uint32_t src_addr,
                                       uint8_t code, void *error_ip_buffer,
                                       size_t len) {
  if (len < sizeof(ip_header) + 8) {  // If error packet is too small
    LOG_ICMP("Error packet is too short\n");
    return;
  }

  // Allocate ICMP header + area of message + error packet section (IP header +
  // bytes)
  my_buf *unreachable_mybuf = my_buf::create(
      sizeof(icmp_header) + sizeof(icmp_destination_unreachable) +
      sizeof(ip_header) + 8);
  auto *unreachable_msg =
      reinterpret_cast<icmp_message *>(unreachable_mybuf->buffer);

  // Set each field
  unreachable_msg->header.type = ICMP_TYPE_DESTINATION_UNREACHABLE;
  unreachable_msg->header.code = code;
  unreachable_msg->header.checksum = 0;
  unreachable_msg->destination_unreachable.unused = 0;
  memcpy(unreachable_msg->destination_unreachable.data, error_ip_buffer,
         sizeof(ip_header) + 8);
  unreachable_msg->header.checksum =
      checksum_16(reinterpret_cast<uint16_t *>(unreachable_mybuf->buffer),
                  unreachable_mybuf->len);

  // Send by IP
  ip_encapsulate_output(dest_addr, src_addr, unreachable_mybuf,
                        IP_PROTOCOL_NUM_ICMP);
}