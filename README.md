# bambu_virtual_client

Client-side library that lets a slicer (BambuStudio or OrcaSlicer) talk to a
Bambu Bridge running elsewhere on the LAN, without going through the
proprietary `libbambu_networking.so` plugin.

## What it provides

The slicer's plugin only knows how to talk MQTT-over-TLS to printers whose
certs chain to Bambu's CA. Bambu Bridge mints self-signed certs, so the
plugin rejects bridge connections with `tlsv1 alert unknown ca`. This library
implements the matching wire protocols (`verify=false`) so the slicer can
treat a bridge-fronted virtual printer the same way it treats a real
on-cloud printer.

Eight translation units:

| File                          | Role                                                          |
|-------------------------------|---------------------------------------------------------------|
| `MqttFraming.{cpp,hpp}`       | MQTT 3.1.1 packet codec (encode PUBLISH, decode CONNACK/PUBLISH/SUBACK/…) |
| `VirtualMqttClient.{cpp,hpp}` | One TLS+MQTT session per virtual `dev_id`, callback-driven    |
| `VirtualFtpsClient.{cpp,hpp}` | Implicit-TLS FTPS uploader for `start_send_gcode_to_sdcard`   |
| `VirtualMqttCli.cpp`          | Standalone `bambu_virtual_cli` testbed                        |
| `VirtualBambuTunnel.{cpp,hpp}`| BambuLib trampolines for `bambu:///virtual/...` tunnel URLs   |
| `VirtualLanPrinterStore.{cpp,hpp}` | JSON persistence of discovered virtual LAN printers      |
| `VirtualSsdpDiscovery.{cpp,hpp}` | SSDP listener that surfaces FFFF bridges to DeviceManager  |

## Who consumes it

Both BambuStudio-bridge and OrcaSlicer-bridge add this repo as a submodule at

```
src/slic3r/Utils/bambu_virtual_client/
```

and `add_subdirectory()` it from `src/slic3r/CMakeLists.txt`, linking
`libslic3r_gui` against the resulting `bambu_virtual_client` static lib.

## Slicer-specific bits that DO NOT live here

This is strictly the client-side wire layer. Per-slicer integration points
stay in the consuming repo:

- `MediaUrlBuilder.{cpp,hpp}` — the bridge-camera URL shape differs per slicer
- The `NetworkAgent` FFFF dispatch switch
- The `DeviceManager::parse_json` virtual-printer gate
- The `PrinterFileSystem` BambuLib pointer install
- The `MediaFilePanel` / `MediaPlayCtrl` virtual-printer branches

The bridge-server-side code (`bambu_bridge/server/...` in BambuStudio-bridge)
also stays out of this lib by design — different namespace, different threading
model, different host program.

## Build (standalone, for CI smoke tests)

```
cmake -S . -B build
cmake --build build -j8
```

Produces `build/libbambu_virtual_client.a`. In standalone mode only the
slicer-agnostic translation units are compiled — the four that need
`GUI_App.hpp` / `DevManager.h` / `BambuTunnel.h` / `libslic3r/Utils.hpp` are
skipped. Set `BAMBU_VIRTUAL_CLIENT_SLIC3R_INCLUDE_DIR`,
`BAMBU_VIRTUAL_CLIENT_SLICER_SRC_DIR` and `BAMBU_VIRTUAL_CLIENT_JSON_INCLUDE_DIR`
to enable the full build.

## Build (as a submodule)

The consuming slicer's CMake passes the four include-dir variables and the
boost include dir. Example wiring from a slicer's `src/slic3r/CMakeLists.txt`:

```cmake
set(BAMBU_VIRTUAL_CLIENT_SLIC3R_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR})
set(BAMBU_VIRTUAL_CLIENT_SLICER_SRC_DIR     ${CMAKE_CURRENT_SOURCE_DIR}/..)
set(BAMBU_VIRTUAL_CLIENT_JSON_INCLUDE_DIR   ${NLOHMANN_JSON_INCLUDE_DIR})
set(BAMBU_VIRTUAL_CLIENT_BOOST_INCLUDE_DIR  ${Boost_INCLUDE_DIRS})
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/Utils/bambu_virtual_client
                 ${CMAKE_BINARY_DIR}/bambu_virtual_client)
target_link_libraries(libslic3r_gui bambu_virtual_client)
```

Then the slicer's `#include` directives reference, e.g.,

```cpp
#include "Utils/bambu_virtual_client/VirtualMqttClient.hpp"
```
