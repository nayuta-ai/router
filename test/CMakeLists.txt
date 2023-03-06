cmake_minimum_required(VERSION 3.13)
project(unittest)
find_package(GTest)

add_executable(interface_test interface_test.cpp)
target_link_libraries(interface_test ${GTEST_BOTH_LIBRARIES} pthread net)
target_include_directories(interface_test PUBLIC ${GTEST_INCLUDE_DIRS} ../include)