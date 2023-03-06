#include <gtest/gtest.h>
#include "interface.h"

TEST(IsIgnoreInterfaceTest, ValidIgnoreInterface){
  const char *ifname = "lo";
  bool result = is_ignore_interface(ifname);
  EXPECT_TRUE(result);
}

TEST(IsIgnoreInterfaceTest, InvalidIgnoreInterface){
  const char *ifname = "eth0";
  bool result = is_ignore_interface(ifname);
  EXPECT_FALSE(result);
}