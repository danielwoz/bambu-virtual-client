# bambu_virtual_client — tests.
#
# Phase 1c: VirtualSsdpJsonContractTest — pins the JSON shape
#           DeviceManager::on_machine_alive expects. Exercises the pure
#           helper extracted to VirtualSsdpAliveJson.{hpp,cpp}; the
#           discovery class itself is slicer-gated and out of reach for
#           a standalone test.
#
# All tests follow the BambuStudio-bridge tests/bridge/ convention:
# no third-party framework, a single int main() that increments a fail
# counter and prints offending vectors. Exit code = number of failed
# assertions (0 = pass).

add_executable(VirtualSsdpJsonContractTest VirtualSsdpJsonContractTest.cpp)
target_link_libraries(VirtualSsdpJsonContractTest PRIVATE bambu_virtual_client)
# Pass the fixture path through so the test doesn't depend on cwd.
target_compile_definitions(VirtualSsdpJsonContractTest PRIVATE
    BVC_TEST_FIXTURES_DIR="${CMAKE_CURRENT_SOURCE_DIR}/fixtures"
)
set_target_properties(VirtualSsdpJsonContractTest PROPERTIES
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED ON
)
add_test(NAME VirtualSsdpJsonContractTest COMMAND VirtualSsdpJsonContractTest)
