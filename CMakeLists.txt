cmake_minimum_required(VERSION 3.17)
project(o1c-gen)

set(CMAKE_CXX_STANDARD 14)
find_package(PkgConfig REQUIRED)
pkg_check_modules(SODIUM REQUIRED IMPORTED_TARGET libsodium)

add_library(libsodium-signcryption STATIC libsodium-signcryption/src/tbsbr/signcrypt_tbsbr.c)
target_link_libraries(libsodium-signcryption PUBLIC PkgConfig::SODIUM)

add_executable(o1c-gen main.cpp)
target_include_directories(o1c-gen PUBLIC libsodium-signcryption/src/tbsbr)
target_link_libraries(o1c-gen PUBLIC libsodium-signcryption)
