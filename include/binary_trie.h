#ifndef CURO_BINARY_TRIE_H
#define CURO_BINARY_TRIE_H

#include <cstdint>
#include <string>

#define IP_BIT_LEN 32

template <typename DATA_TYPE>
struct binary_trie_node {    // Nodes in a binary tri-tree structure
  DATA_TYPE *data;           // Data to be retained
  uint32_t depth;            // Depths from root node
  binary_trie_node *parent;  // Parent Node
  binary_trie_node *node_0;  // 0-side child node
  binary_trie_node *node_1;  // 1-side child node
};

/**
 * Create a node in a tree structure.
 * @tparam DATA_TYPE
 * @param root
 * @param prefix
 * @param prefix_len
 * @param data
 */
template <typename DATA_TYPE>
void binary_trie_add(binary_trie_node<DATA_TYPE> *root, uint32_t prefix,
                     uint32_t prefix_len, DATA_TYPE *data) {
  binary_trie_node<DATA_TYPE> *current = root;  // Trace from the root node
  // Trace the branch
  for (int i = 1; i <= prefix_len; ++i) {
    if ((prefix >> (IP_BIT_LEN - i)) &
        0x01) {  // if the i-th bit from the top is 1
      if (current->node_1 ==
          nullptr) {  // if there is no branch to follow, make
        current->node_1 = (binary_trie_node<DATA_TYPE> *)calloc(
            1, sizeof(binary_trie_node<DATA_TYPE>));
        current->node_1->data = 0;
        current->node_1->depth = i;
        current->node_1->parent = current;
      }
      current = current->node_1;
    } else {  // if the i-th bit from the top is 0
      if (current->node_0 ==
          nullptr) {  // if there is no branch to follow, make
        current->node_0 = (binary_trie_node<DATA_TYPE> *)calloc(
            1, sizeof(binary_trie_node<DATA_TYPE>));
        current->node_0->data = 0;
        current->node_0->depth = i;
        current->node_0->parent = current;
      }
      current = current->node_0;
    }
  }

  current->data = data;  // set data
}

/**
 * Search for a tri-tree by prefix.
 * @tparam DATA_TYPE
 * @param root
 * @param prefix
 * @return
 */
template <typename DATA_TYPE>
DATA_TYPE *binary_trie_search(binary_trie_node<DATA_TYPE> *root,
                              uint32_t prefix) {  // search
  binary_trie_node<DATA_TYPE> *current = root;    // traverse from root node
  DATA_TYPE *result = nullptr;
  // Trace back one bit at a time compared to the IP address to be searched for
  for (int i = 1; i <= IP_BIT_LEN; ++i) {
    if (current->data != nullptr) {
      result = current->data;
    }
    if ((prefix >> (IP_BIT_LEN - i)) &
        0x01) {  // if the i-th bit from the top is 1
      if (current->node_1 == nullptr) {
        return result;
      }
      current = current->node_1;
    } else {  // if the first bit is 0
      if (current->node_0 == nullptr) {
        return result;
      }
      current = current->node_0;
    }
  }
  return result;
}

#endif  // CURO_BINARY_TRIE_H