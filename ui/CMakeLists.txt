cmake_minimum_required(VERSION 3.24)
project(cachybridge_setup VERSION 4.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)

find_package(Qt6 6.6 REQUIRED COMPONENTS Widgets)

qt_add_executable(cachybridge-setup
    src/main.cpp
)
target_link_libraries(cachybridge-setup PRIVATE Qt6::Widgets)

include(GNUInstallDirs)
install(TARGETS cachybridge-setup RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
