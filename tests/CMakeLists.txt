# bambu_virtual_client — tests.
#
# Phase 1a: MqttFramingTest    — wire-format codec pin for the public API
#                                 (decode_packet + encode_publish). Indirectly
#                                 exercises the file-static varint helper via
#                                 payload-size variations across the 0/127/128/
#                                 16383/16384 boundaries.
# Phase 1b: VirtualMqttClientLoopbackTest  (placeholder — added later)
# Phase 1c: VirtualSsdpJsonContractTest    (placeholder — added later)
# Phase 1d: VirtualLanPrinterStorePersistTest (placeholder — added later)
# Phase 1e: VirtualFtpsClientLoopbackTest  (placeholder — added later)
#
# All tests use the same convention as BambuStudio-bridge's tests/bridge/:
# no third-party framework, a single int main() that increments a fail
# counter and prints offending vectors. Exit code = number of failed
# assertions (0 = pass). Loopback tests that can't bind their port
# return ctest skip code 77 instead of failing.

add_executable(MqttFramingTest MqttFramingTest.cpp)
target_link_libraries(MqttFramingTest PRIVATE bambu_virtual_client)
set_target_properties(MqttFramingTest PROPERTIES
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED ON
)
add_test(NAME MqttFramingTest COMMAND MqttFramingTest)

# Phase 1d — VirtualLanPrinterStore persist/hydrate round-trip.
# Drives the JSON-on-disk store via the in_dir() factory added in this
# phase, so the standalone build (no Slic3r::data_dir()) can still
# exercise it against per-subtest /tmp directories.
add_executable(VirtualLanPrinterStorePersistTest
    VirtualLanPrinterStorePersistTest.cpp)
target_link_libraries(VirtualLanPrinterStorePersistTest
    PRIVATE bambu_virtual_client)
# The test uses boost::filesystem directly; bambu_virtual_client.a
# links it statically but doesn't re-export the shared lib, so the
# test target has to find it on its own. find_package(Boost ...
# COMPONENTS filesystem) only works when the boost_filesystem cmake
# config is installed (it isn't on slim Debian/Ubuntu hosts), so fall
# back to find_library() against the SONAME-versioned .so the runtime
# package ships.
find_package(Boost QUIET COMPONENTS filesystem)
if(TARGET Boost::filesystem)
    target_link_libraries(VirtualLanPrinterStorePersistTest
        PRIVATE Boost::filesystem)
else()
    find_library(BVC_BOOST_FILESYSTEM_LIB
        NAMES boost_filesystem
              libboost_filesystem.so.1.74.0
              libboost_filesystem.so.1.83.0)
    if(BVC_BOOST_FILESYSTEM_LIB)
        target_link_libraries(VirtualLanPrinterStorePersistTest
            PRIVATE ${BVC_BOOST_FILESYSTEM_LIB})
    else()
        message(FATAL_ERROR
            "VirtualLanPrinterStorePersistTest: boost_filesystem not found")
    endif()
endif()
set_target_properties(VirtualLanPrinterStorePersistTest PROPERTIES
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED ON
)
add_test(NAME VirtualLanPrinterStorePersistTest
         COMMAND VirtualLanPrinterStorePersistTest)
