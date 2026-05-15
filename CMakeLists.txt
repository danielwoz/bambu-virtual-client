# bambu_virtual_client — client-side library that lets a slicer (BambuStudio or
# OrcaSlicer) talk to a Bambu Bridge instance running elsewhere on the LAN.
#
# This target is meant to be consumed as a git submodule by both slicers and
# built via add_subdirectory(). It also builds standalone (only the
# slicer-independent translation units are compiled in that mode), which is
# useful for CI smoke-testing the wire layer in isolation.
#
# Required external dependencies:
#   - OpenSSL  (TLS for MQTT-over-TLS and implicit-TLS FTPS)
#   - Threads  (per-session I/O threads)
#   - Boost    (header-only — boost::asio, boost::log, boost::filesystem,
#              boost::algorithm, boost::property_tree). Bring your own.
#   - nlohmann/json (header-only — used by VirtualSsdpDiscovery to shape the
#              alive-JSON DeviceManager::on_machine_alive consumes)
#
# Consumer-supplied bits (only needed when integrating into a slicer):
#   - BAMBU_VIRTUAL_CLIENT_SLIC3R_INCLUDE_DIR    -> path to <slicer>/src/slic3r
#       so the lib can find GUI/GUI_App.hpp, GUI/DeviceCore/DevManager.h,
#       GUI/Printer/BambuTunnel.h
#   - BAMBU_VIRTUAL_CLIENT_SLICER_SRC_DIR        -> path to <slicer>/src
#       so the lib can find libslic3r/Utils.hpp (Slic3r::data_dir())
#   - BAMBU_VIRTUAL_CLIENT_JSON_INCLUDE_DIR      -> include dir for
#       <nlohmann/json.hpp>
#   - BAMBU_VIRTUAL_CLIENT_BOOST_INCLUDE_DIR     -> include dir for boost
#       headers (often already supplied via target_link_libraries(Boost::*))
#
# When all three slicer-side variables resolve to non-empty paths the full
# library (8 translation units) is built. Otherwise only the slicer-agnostic
# subset is built so the target still produces libbambu_virtual_client.a.

cmake_minimum_required(VERSION 3.13)
project(bambu_virtual_client CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# ---- Dependencies ----------------------------------------------------------

find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)

# Boost is header-only for this lib; allow the consuming project to supply the
# include dir directly when find_package(Boost) is too heavy.
if(NOT BAMBU_VIRTUAL_CLIENT_BOOST_INCLUDE_DIR)
    find_package(Boost QUIET COMPONENTS filesystem log)
    if(Boost_FOUND)
        set(BAMBU_VIRTUAL_CLIENT_BOOST_INCLUDE_DIR ${Boost_INCLUDE_DIRS})
    endif()
endif()

# ---- Source list -----------------------------------------------------------

# Always-buildable (no slicer dependency).
set(_bvc_sources_core
    MqttFraming.cpp
    MqttFraming.hpp
    VirtualMqttClient.cpp
    VirtualMqttClient.hpp
    VirtualFtpsClient.cpp
    VirtualFtpsClient.hpp
)

# Translation units that need slicer-supplied headers.
set(_bvc_sources_slicer
    VirtualBambuTunnel.cpp
    VirtualBambuTunnel.hpp
    VirtualLanPrinterStore.cpp
    VirtualLanPrinterStore.hpp
    VirtualSsdpDiscovery.cpp
    VirtualSsdpDiscovery.hpp
)

set(_bvc_have_slicer FALSE)
if(BAMBU_VIRTUAL_CLIENT_SLIC3R_INCLUDE_DIR
   AND BAMBU_VIRTUAL_CLIENT_SLICER_SRC_DIR
   AND BAMBU_VIRTUAL_CLIENT_JSON_INCLUDE_DIR)
    set(_bvc_have_slicer TRUE)
endif()

set(_bvc_sources ${_bvc_sources_core})
if(_bvc_have_slicer)
    list(APPEND _bvc_sources ${_bvc_sources_slicer})
endif()

# ---- Target ----------------------------------------------------------------

add_library(bambu_virtual_client STATIC ${_bvc_sources})

target_include_directories(bambu_virtual_client
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
)

if(BAMBU_VIRTUAL_CLIENT_BOOST_INCLUDE_DIR)
    target_include_directories(bambu_virtual_client SYSTEM PUBLIC
        ${BAMBU_VIRTUAL_CLIENT_BOOST_INCLUDE_DIR})
endif()

if(BAMBU_VIRTUAL_CLIENT_JSON_INCLUDE_DIR)
    target_include_directories(bambu_virtual_client SYSTEM PUBLIC
        ${BAMBU_VIRTUAL_CLIENT_JSON_INCLUDE_DIR})
endif()

if(_bvc_have_slicer)
    # PUBLIC: the lib's headers transitively #include "BambuTunnel.h" and
    # rely on the slicer's bambu_networking.hpp / GUI_App.hpp on the include
    # path. Consumers (libslic3r_gui) need to see those headers too.
    target_include_directories(bambu_virtual_client PUBLIC
        ${BAMBU_VIRTUAL_CLIENT_SLIC3R_INCLUDE_DIR}
        ${BAMBU_VIRTUAL_CLIENT_SLICER_SRC_DIR}
        ${BAMBU_VIRTUAL_CLIENT_SLIC3R_INCLUDE_DIR}/GUI/Printer
    )
    # Extra include dirs (typically the generated header tree under
    # ${CMAKE_BINARY_DIR}/src/libslic3r/, ${CMAKE_BINARY_DIR}/src/slic3r/)
    if(BAMBU_VIRTUAL_CLIENT_EXTRA_INCLUDE_DIRS)
        target_include_directories(bambu_virtual_client PRIVATE
            ${BAMBU_VIRTUAL_CLIENT_EXTRA_INCLUDE_DIRS})
    endif()
endif()

target_link_libraries(bambu_virtual_client
    PUBLIC
        OpenSSL::SSL
        OpenSSL::Crypto
        Threads::Threads
)

if(NOT _bvc_have_slicer)
    message(STATUS "bambu_virtual_client: building slicer-agnostic subset only "
                   "(set BAMBU_VIRTUAL_CLIENT_SLIC3R_INCLUDE_DIR, "
                   "BAMBU_VIRTUAL_CLIENT_SLICER_SRC_DIR, "
                   "BAMBU_VIRTUAL_CLIENT_JSON_INCLUDE_DIR to enable the full build)")
endif()

# ---- Optional CLI testbed --------------------------------------------------

option(BAMBU_VIRTUAL_CLIENT_BUILD_CLI
       "Build the bambu_virtual_cli standalone testbed binary" ON)

if(BAMBU_VIRTUAL_CLIENT_BUILD_CLI)
    add_executable(bambu_virtual_cli VirtualMqttCli.cpp)
    target_link_libraries(bambu_virtual_cli PRIVATE bambu_virtual_client)
endif()
