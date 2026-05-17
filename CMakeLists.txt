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
#   - BAMBU_VIRTUAL_CLIENT_WX_INCLUDE_DIRS       -> wxWidgets include dirs
#       (typically ${wxWidgets_INCLUDE_DIRS} after find_package(wxWidgets)).
#       VirtualSsdpDiscovery.cpp transitively includes slicer headers that
#       pull in <wx/setup.h>; without this var the build fails on Windows
#       and on any host where wx isn't on the default include path.
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
#
# VirtualSsdpAliveJson.{hpp,cpp} is the pure JSON builder split out of
# VirtualSsdpDiscovery so the schema contract (the keys
# DeviceManager::on_machine_alive parses) can be pinned by a standalone
# test without dragging slicer headers in. Depends on nlohmann/json.
#
# VirtualLanPrinterStore.cpp soft-depends on libslic3r/Utils.hpp via
# __has_include — when the slicer headers are on the include path the
# default ctor resolves the path through Slic3r::data_dir() exactly as
# before; standalone builds (no slicer headers) require the caller to
# supply a path via the ctor or in_dir() factory. Either way the TU
# itself always compiles, so the file lives in _bvc_sources_core.
set(_bvc_sources_core
    MqttFraming.cpp
    MqttFraming.hpp
    VirtualMqttClient.cpp
    VirtualMqttClient.hpp
    VirtualFtpsClient.cpp
    VirtualFtpsClient.hpp
    VirtualSsdpAliveJson.cpp
    VirtualSsdpAliveJson.hpp
    VirtualLanPrinterStore.cpp
    VirtualLanPrinterStore.hpp
)

# nlohmann/json auto-detection — only kicks in when the consumer didn't
# already point us at a copy. Lets `cmake -S . -B build` "just work" on a
# vanilla checkout for the standalone-test path.
if(NOT BAMBU_VIRTUAL_CLIENT_JSON_INCLUDE_DIR)
    find_path(BAMBU_VIRTUAL_CLIENT_JSON_INCLUDE_DIR
              NAMES nlohmann/json.hpp)
endif()
if(NOT BAMBU_VIRTUAL_CLIENT_JSON_INCLUDE_DIR)
    message(FATAL_ERROR
        "bambu_virtual_client: nlohmann/json.hpp not found. Set "
        "BAMBU_VIRTUAL_CLIENT_JSON_INCLUDE_DIR to the include dir "
        "containing <nlohmann/json.hpp> (the slicer build supplies this "
        "automatically).")
endif()

# Translation units that need slicer-supplied headers.
set(_bvc_sources_slicer
    VirtualBambuTunnel.cpp
    VirtualBambuTunnel.hpp
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
    # wxWidgets include dirs: VirtualSsdpDiscovery.cpp uses wxGetApp() /
    # CallAfter(), and slicer headers it pulls in transitively #include
    # <wx/setup.h>. Required on Windows (where wx isn't on the default
    # include path) and any host that didn't already add wx headers
    # globally.
    if(BAMBU_VIRTUAL_CLIENT_WX_INCLUDE_DIRS)
        target_include_directories(bambu_virtual_client SYSTEM PUBLIC
            ${BAMBU_VIRTUAL_CLIENT_WX_INCLUDE_DIRS})
    endif()
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

# ---- Tests -----------------------------------------------------------------
#
<<<<<<< HEAD
# Default ON when built standalone (the project is the top-level CMake
# project), OFF when consumed as a subdirectory by a slicer — keeps the
# slicer build clean of test binaries and ctest registrations.
=======
# Default ON when built standalone (PROJECT_IS_TOP_LEVEL), OFF when consumed
# as a subdirectory by a slicer — keeps the slicer build clean of test
# binaries and ctest registrations.
>>>>>>> phase1d-lanstore-persist
if(NOT DEFINED BAMBU_VIRTUAL_CLIENT_BUILD_TESTS)
    if(CMAKE_PROJECT_NAME STREQUAL PROJECT_NAME)
        set(BAMBU_VIRTUAL_CLIENT_BUILD_TESTS_DEFAULT ON)
    else()
        set(BAMBU_VIRTUAL_CLIENT_BUILD_TESTS_DEFAULT OFF)
    endif()
endif()
option(BAMBU_VIRTUAL_CLIENT_BUILD_TESTS
<<<<<<< HEAD
       "Build bambu_virtual_client unit + loopback + contract tests"
=======
       "Build bambu_virtual_client unit + loopback tests"
>>>>>>> phase1d-lanstore-persist
       ${BAMBU_VIRTUAL_CLIENT_BUILD_TESTS_DEFAULT})

if(BAMBU_VIRTUAL_CLIENT_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()
