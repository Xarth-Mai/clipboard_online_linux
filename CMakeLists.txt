cmake_minimum_required(VERSION 3.29)
project(clipboard_online_linux)

set(CMAKE_CXX_STANDARD 20)

# 查找 OpenSSL 包
find_package(OpenSSL REQUIRED)

# 创建可执行文件
add_executable(clipboard_online_linux main.cpp)

# 链接 OpenSSL 库
target_link_libraries(clipboard_online_linux OpenSSL::Crypto OpenSSL::SSL)
