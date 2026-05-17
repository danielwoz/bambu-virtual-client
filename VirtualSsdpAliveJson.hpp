// VirtualSsdpAliveJson — pure JSON builder for the alive payload
// `DeviceManager::on_machine_alive(std::string)` consumes.
//
// Split out of VirtualSsdpDiscovery so the schema can be pinned by a
// standalone contract test without dragging in the slicer's wxWidgets /
// GUI_App / DeviceManager headers. The discovery class itself still
// needs those (it calls wxGetApp().CallAfter and DeviceManager
// directly), so its translation unit stays in the slicer-gated source
// list while this helper lives in the always-buildable core.
//
// Schema reference (both slicers parse the same keys):
//   BambuStudio-bridge   src/slic3r/GUI/DeviceCore/DevManager.cpp
//                        DeviceManager::on_machine_alive
//   OrcaSlicer-bridge    src/slic3r/GUI/DeviceCore/DevManager.cpp
//                        DeviceManager::on_machine_alive
//
// Required keys:  dev_name, dev_id, dev_ip, dev_type, dev_signal,
//                 connect_type, bind_state
// Optional keys:  sec_link, ssdp_version   (only emitted when non-empty)

#ifndef SLIC3R_VIRTUAL_SSDP_ALIVE_JSON_HPP
#define SLIC3R_VIRTUAL_SSDP_ALIVE_JSON_HPP

#include <string>

namespace Slic3r {

// Plain-data view of a single SSDP-discovered (or hydrated) virtual
// printer. The members map 1:1 onto the JSON keys
// `DeviceManager::on_machine_alive` parses, with two normalization
// rules applied by `build_alive_json`:
//
//   - `connect_type` defaults to "lan" if left empty (the bridge always
//     speaks LAN; we never emit cloud paths)
//   - `bind_state` defaults to "free" if left empty (matches the
//     slicer's behaviour when a printer reports no bind info)
//
// Optional fields (`sec_link`, `ssdp_version`) are only emitted in the
// output JSON when non-empty — DeviceManager reads them via
// `j.contains(...)` so omitting them is the same as sending "".
struct AliveInfo {
    std::string dev_name;
    std::string dev_id;
    std::string dev_ip;
    std::string dev_type;
    std::string dev_signal;
    std::string connect_type;   // default "lan"
    std::string bind_state;     // default "free"
    std::string sec_link;       // optional
    std::string ssdp_version;   // optional
};

// Serialize `info` to the exact JSON shape DeviceManager::on_machine_alive
// expects. Applies the defaulting rules described above.
std::string build_alive_json(const AliveInfo& info);

} // namespace Slic3r

#endif // SLIC3R_VIRTUAL_SSDP_ALIVE_JSON_HPP
