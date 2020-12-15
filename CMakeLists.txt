cmake_minimum_required(VERSION 3.17)
project(o1c)

set(CMAKE_CXX_STANDARD 14)
find_package(PkgConfig REQUIRED)
pkg_check_modules(SODIUM REQUIRED IMPORTED_TARGET libsodium)

add_library(sodium-signcryption STATIC libsodium-signcryption/src/tbsbr/signcrypt_tbsbr.c)
target_link_libraries(sodium-signcryption PUBLIC PkgConfig::SODIUM)

add_executable(o1c-sc main.cpp signcrypt.cpp)
target_include_directories(o1c-sc PUBLIC libsodium-signcryption/src/tbsbr)
target_link_libraries(o1c-sc PUBLIC PkgConfig::SODIUM sodium-signcryption)
