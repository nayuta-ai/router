cmake_minimum_required(VERSION 3.13)
project(net)
add_library(net STATIC interface.cpp net.cpp device.cpp)
target_include_directories(net INTERFACE ../include)