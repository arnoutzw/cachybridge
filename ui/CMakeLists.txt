cmake_minimum_required(VERSION 3.24)
project(cachybridge_setup VERSION 4.1.1 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)

find_package(Qt6 6.6 REQUIRED COMPONENTS Network Widgets)
find_package(KF6StatusNotifierItem 6.6 REQUIRED)

qt_add_executable(cachybridge-setup
    src/main.cpp
)
target_link_libraries(cachybridge-setup PRIVATE Qt6::Network Qt6::Widgets)

qt_add_executable(cachybridge-tray
    src/tray.cpp
)
target_link_libraries(cachybridge-tray PRIVATE Qt6::Network Qt6::Widgets KF6::StatusNotifierItem)

include(GNUInstallDirs)
install(TARGETS cachybridge-setup cachybridge-tray RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
