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
