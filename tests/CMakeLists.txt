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
