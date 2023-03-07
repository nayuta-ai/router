#ifndef CURO_MY_BUF_H
#define CURO_MY_BUF_H

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>

struct my_buf {
  my_buf *previous = nullptr;  // Previous my_buf
  my_buf *next = nullptr;      // Back my_buf
  uint32_t len = 0;            // Length of buffer contained in my_buf
  uint8_t buffer[];            // Buffer

  /**
   * Allocate memory for my_buf
   * @param len Buffer length to be allocated
   */
  static my_buf *create(uint32_t len) {
    auto *buf = (my_buf *)calloc(1, sizeof(my_buf) + len);
    buf->len = len;
    return buf;
  }

  /**
   * Release the memory of my_buf
   * @param buf
   * @param is_recursive
   */
  static void my_buf_free(my_buf *buf, bool is_recursive = false) {
    if (!is_recursive) {
      free(buf);
      return;
    }

    my_buf *tail = buf->get_tail(), *tmp;
    while (tail != nullptr) {
      tmp = tail;
      tail = tmp->previous;
      free(tmp);
    }
  }

  /**
   * Returns the last item in the chained list
   */
  my_buf *get_tail() {
    my_buf *current = this;
    while (current->next != nullptr) {
      current = current->next;
    }
    return current;
  }

  void add_header(my_buf *buf) {
    this->previous = buf;
    buf->next = this;
  }
};

#endif  // CURO_MY_BUF_H