# bambu_virtual_client — tests.
#
# Phase 1a: MqttFramingTest                — wire-format codec pin for the
#                                            public API (decode_packet +
#                                            encode_publish). Exercises varint
#                                            indirectly via PUBLISH payload-size
#                                            boundaries (0/127/128/16383/16384).
# Phase 1b: VirtualMqttClientLoopbackTest  — TLS/MQTT loopback against a
#                                            hermetic in-test broker.
# Phase 1c: VirtualSsdpJsonContractTest    — pins the JSON shape
#                                            DeviceManager::on_machine_alive
#                                            expects (exercises the pure
#                                            VirtualSsdpAliveJson helper).
# Phase 1d: VirtualLanPrinterStorePersistTest — persist/hydrate round-trip via
#                                            in_dir() factory against per-test
#                                            /tmp dirs.
# Phase 1e: VirtualFtpsClientLoopbackTest  — implicit-TLS FTPS loopback upload
#                                            against an in-test minimal FTPS
#                                            server (USER/PASS, PASV, STOR,
#                                            QUIT). Skips with ctest 77 on
#                                            loopback bind failure.
#
# All tests follow the BambuStudio-bridge tests/bridge/ convention:
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

# Phase 1b — TLS/MQTT loopback against a hermetic in-test broker. Links
# OpenSSL directly: the test mints its own self-signed cert + runs
# TLS_server_method, neither of which the library proper needs.
add_executable(VirtualMqttClientLoopbackTest VirtualMqttClientLoopbackTest.cpp)
target_link_libraries(VirtualMqttClientLoopbackTest
    PRIVATE
        bambu_virtual_client
        OpenSSL::SSL
        OpenSSL::Crypto
)
set_target_properties(VirtualMqttClientLoopbackTest PROPERTIES
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED ON
)
add_test(NAME VirtualMqttClientLoopbackTest
         COMMAND VirtualMqttClientLoopbackTest)
set_tests_properties(VirtualMqttClientLoopbackTest PROPERTIES
    SKIP_RETURN_CODE 77
)

# Phase 1c — SSDP JSON contract pin via the extracted helper.
add_executable(VirtualSsdpJsonContractTest VirtualSsdpJsonContractTest.cpp)
target_link_libraries(VirtualSsdpJsonContractTest PRIVATE bambu_virtual_client)
target_compile_definitions(VirtualSsdpJsonContractTest PRIVATE
    BVC_TEST_FIXTURES_DIR="${CMAKE_CURRENT_SOURCE_DIR}/fixtures"
)
set_target_properties(VirtualSsdpJsonContractTest PROPERTIES
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED ON
)
add_test(NAME VirtualSsdpJsonContractTest COMMAND VirtualSsdpJsonContractTest)

# Phase 1d — VirtualLanPrinterStore persist/hydrate round-trip.
# Uses the in_dir() factory added in this phase, so the standalone build
# (no Slic3r::data_dir()) can still exercise it against per-subtest tmpdirs.
# Test calls boost::filesystem directly; bambu_virtual_client.a links it
# statically but doesn't re-export, so this target needs to find it on its
# own.
add_executable(VirtualLanPrinterStorePersistTest
    VirtualLanPrinterStorePersistTest.cpp)
target_link_libraries(VirtualLanPrinterStorePersistTest
    PRIVATE bambu_virtual_client)
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

# Phase 1e — implicit-TLS FTPS loopback. Links OpenSSL directly: the test
# spins its own self-signed TLS FTPS server on 127.0.0.1:random.
add_executable(VirtualFtpsClientLoopbackTest VirtualFtpsClientLoopbackTest.cpp)
target_link_libraries(VirtualFtpsClientLoopbackTest
    PRIVATE
        bambu_virtual_client
        OpenSSL::SSL
        OpenSSL::Crypto
)
set_target_properties(VirtualFtpsClientLoopbackTest PROPERTIES
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED ON
)
add_test(NAME VirtualFtpsClientLoopbackTest COMMAND VirtualFtpsClientLoopbackTest)
set_tests_properties(VirtualFtpsClientLoopbackTest PROPERTIES
    SKIP_RETURN_CODE 77
)
