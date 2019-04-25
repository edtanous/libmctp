cmake_minimum_required(VERSION 3.5 FATAL_ERROR)

add_definitions(-DMCTP_LOG_STDERR)
add_definitions(-DMCTP_FILEIO)

add_library(mctp STATIC alloc.c core.c libmctp.h serial.c smbus.c crc32c.c)

target_include_directories(mctp
                           PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
                                  $<INSTALL_INTERFACE:include/mctp)
target_link_libraries(mctp PUBLIC i2c)

enable_testing()

add_executable(mctp-in-test tests/mctp-in.c)
target_link_libraries(mctp-in-test mctp)

add_executable(mctp-pipe-test tests/mctp-pipe.c)
target_link_libraries(mctp-pipe-test mctp)

add_executable(mctp-smbus-test tests/mctp-smbus.c crc32c.c)
target_link_libraries(mctp-smbus-test mctp i2c)
install(TARGETS mctp-smbus-test DESTINATION bin)

install(TARGETS mctp DESTINATION lib)
install(FILES libmctp.h libmctp-smbus.h libmctp-serial.h nvme-mi.h crc32c.h DESTINATION include/mctp)
