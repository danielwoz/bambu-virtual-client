// VirtualSsdpDiscovery — SSDP listener for FFFF-prefixed Bambu bridges.
//
// The proprietary `libbambu_networking.so` plugin runs its own SSDP
// scanner; when it's absent (the headline scenario for the
// virtual-printer flow) OrcaSlicer has no way to learn that a Bambu
// Bridge is on the LAN. This class fills that gap with a plain
// `boost::asio` UDP listener bound to the SSDP multicast group
// (239.255.255.250:1900). It:
//
//   1. Joins the multicast group on the wildcard interface, with
//      SO_REUSEADDR so we coexist with avahi / the plugin / etc.
//   2. Sends an M-SEARCH on start and every 60 s thereafter to nudge
//      bridges into replying immediately rather than waiting for the
//      next periodic NOTIFY (which the bridge emits every 30 s).
//   3. Parses inbound M-SEARCH-200-OK / NOTIFY-alive packets and
//      filters to entries whose `USN` starts with "FFFF".
//   4. For each FFFF entry, builds the same JSON shape
//      `DeviceManager::on_machine_alive` expects (dev_name, dev_id,
//      dev_ip, dev_type, dev_signal, connect_type, bind_state, …) and
//      dispatches it on the wx main thread via `wxGetApp().CallAfter`.
//   5. Persists the discovery via `VirtualLanPrinterStore` so the next
//      slicer session hydrates the printer list before SSDP catches up.
//
// Owned by `GUI_App` as a `unique_ptr` — constructed after
// DeviceManager exists, destroyed before DeviceManager is freed.

#ifndef SLIC3R_VIRTUAL_SSDP_DISCOVERY_HPP
#define SLIC3R_VIRTUAL_SSDP_DISCOVERY_HPP

#include <cstdint>
#include <memory>
#include <string>

namespace Slic3r {

class VirtualSsdpDiscovery {
public:
    VirtualSsdpDiscovery();
    ~VirtualSsdpDiscovery();

    VirtualSsdpDiscovery(const VirtualSsdpDiscovery&)            = delete;
    VirtualSsdpDiscovery& operator=(const VirtualSsdpDiscovery&) = delete;

    // Bring the listener up. Joins the multicast group, starts the
    // I/O thread, and fires the first M-SEARCH. Idempotent.
    void start();

    // Tear the listener down. Stops the I/O thread, closes the socket.
    // Safe to call when never started or after a previous stop.
    void stop();

    // --- Per-printer MQTT port resolution (no manual config required) ---
    //
    // The bridge advertises one MQTT port per virtual printer via the
    // `Bambu-Mqtt-Port` SSDP header. These statics let the VirtualMqttClient
    // port resolver obtain that port automatically instead of falling back
    // to the 8883 default (which is only correct for one printer):
    //
    //   advertised_port() returns the latest port the running listener has
    //   recorded for `dev_id` from any NOTIFY / M-SEARCH reply (0 if none
    //   seen yet — process-wide, thread-safe cache).
    //
    //   probe_port() is the cold-cache fallback: it sends a synchronous
    //   UNICAST M-SEARCH straight to the known bridge IP (reliable on
    //   networks that drop multicast / behind a host firewall) and caches
    //   every port in the reply, returning the one for `dev_id` (0 on
    //   timeout). Safe to call with no listener running.
    static uint16_t advertised_port(const std::string& dev_id);
    static uint16_t probe_port(const std::string& bridge_ip,
                               const std::string& dev_id,
                               int timeout_ms = 800);

private:
    struct Impl;
    std::unique_ptr<Impl> m_impl;
};

} // namespace Slic3r

#endif // SLIC3R_VIRTUAL_SSDP_DISCOVERY_HPP
