// VirtualSsdpAliveJson — implementation of the pure alive-JSON builder.
// See the header for the schema contract this serializer pins.

#include "VirtualSsdpAliveJson.hpp"

#include <nlohmann/json.hpp>

namespace Slic3r {

std::string build_alive_json(const AliveInfo& info) {
    nlohmann::json j;
    j["dev_name"]     = info.dev_name;
    j["dev_id"]       = info.dev_id;
    j["dev_ip"]       = info.dev_ip;
    j["dev_type"]     = info.dev_type;
    j["dev_signal"]   = info.dev_signal;
    // FFFF entries live on a LAN — the bridge IS the LAN endpoint. We
    // never emit cloud paths, so default empty to "lan" rather than
    // forcing every callsite to spell it out.
    j["connect_type"] = info.connect_type.empty() ? "lan" : info.connect_type;
    // DevBind: "free" / "occupied". Default empty to "free" so the
    // slicer's Add-Printer flow shows the bind button on first sight.
    j["bind_state"]   = info.bind_state.empty() ? "free" : info.bind_state;
    // Optional fields DeviceManager reads via j.contains(); only emit
    // when non-empty so the wire shape stays minimal.
    if (!info.sec_link.empty())     j["sec_link"]     = info.sec_link;
    if (!info.ssdp_version.empty()) j["ssdp_version"] = info.ssdp_version;
    return j.dump();
}

} // namespace Slic3r
