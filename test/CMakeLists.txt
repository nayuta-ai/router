cmake_minimum_required(VERSION 3.13)
project(unittest)
find_package(GTest)

# Define a list of source files
set(SOURCES interface_test.cpp utils_test.cpp config_test.cpp ip_test.cpp arp_test.cpp device_test.cpp)

# Loop over the source files and create a target for each one
foreach(SOURCE ${SOURCES})
  # Extract the base name of the source file (without extension)
  get_filename_component(TARGET ${SOURCE} NAME_WE)

  # Create the target and add the source file
  add_executable(${TARGET} ${SOURCE})

  # Add include directories
  target_include_directories(${TARGET} PUBLIC ${GTEST_INCLUDE_DIRS} ../include)

  # Link the target to the socket library (if needed)
  target_link_libraries(${TARGET} ${GTEST_BOTH_LIBRARIES} pthread net gmock gmock_main)
endforeach()