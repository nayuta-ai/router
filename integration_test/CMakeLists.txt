cmake_minimum_required(VERSION 3.13)
project(integration)
find_package(GTest)

add_executable(integration_test test.cpp)
target_link_libraries(integration_test ${GTEST_BOTH_LIBRARIES} pthread net gmock gmock_main)
target_include_directories(interface_test PUBLIC ${GTEST_INCLUDE_DIRS} ../include)