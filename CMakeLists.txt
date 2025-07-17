cmake_minimum_required(VERSION 3.10)
project(proxy_re_encryption)

set(CMAKE_CXX_STANDARD 17)

find_library(PBC_LIB pbc)
find_library(GMP_LIB gmp)

include_directories(include)
include_directories(/usr/local/include)

add_executable(cloud_server src/cloud_server.cpp src/common/pre_scheme.cpp src/common/network_utils.cpp)
add_executable(data_owner src/data_owner.cpp src/common/pre_scheme.cpp src/common/network_utils.cpp)
add_executable(data_user src/data_user.cpp src/common/pre_scheme.cpp src/common/network_utils.cpp)

target_link_libraries(cloud_server ${PBC_LIB} ${GMP_LIB})
target_link_libraries(data_owner ${PBC_LIB} ${GMP_LIB})
target_link_libraries(data_user ${PBC_LIB} ${GMP_LIB})
