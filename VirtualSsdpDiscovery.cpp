// VirtualSsdpDiscovery implementation. See header for design.

#include "VirtualSsdpDiscovery.hpp"

#include "StructuredLog.hpp"          // BBL_LOG — env-gated JSONL diagnostics
#include "VirtualLanPrinterStore.hpp"
#include "VirtualSsdpAliveJson.hpp"  // pure JSON builder (standalone-testable)
// Resolved from the consuming slicer's src/slic3r/ include path,
// supplied to this library by the parent CMake project (see
// BAMBU_VIRTUAL_CLIENT_SLIC3R_INCLUDE_DIR).
#include "GUI/GUI_App.hpp"
#include "GUI/DeviceCore/DevManager.h"

#include <boost/asio.hpp>
#include <boost/algorithm/string/predicate.hpp>
#include <boost/algorithm/string/case_conv.hpp>
#include <boost/algorithm/string/trim.hpp>
#include <boost/log/trivial.hpp>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>

namespace Slic3r {

namespace {

namespace asio = boost::asio;
using boost::asio::ip::udp;

constexpr const char* kSsdpMulticastIPv4 = "239.255.255.250";
constexpr uint16_t    kSsdpPort          = 1900;
constexpr const char* kBambuST           = "urn:bambulab-com:device:3dprinter:1";
constexpr int         kRepProbeSeconds   = 60;

// Trim whitespace + ASCII-lowercase a header key for case-insensitive compare.
std::string lc_trim(std::string s) {
    boost::algorithm::trim(s);
    boost::algorithm::to_lower(s);
    return s;
}

// Parse a CRLF-separated header block (with the request/status line on
// top) into a header_name → value map. Header names are lower-cased so
// callers can probe with `headers["devname.bambu.com"]` regardless of
// the wire casing (real printers send mixed case).
std::map<std::string, std::string>
parse_headers(const std::string& payload) {
    std::map<std::string, std::string> out;
    std::istringstream iss(payload);
    std::string line;
    bool first = true;
    while (std::getline(iss, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (first) { first = false; continue; }
        if (line.empty()) continue;
        auto colon = line.find(':');
        if (colon == std::string::npos) continue;
        std::string key = line.substr(0, colon);
        std::string val = line.substr(colon + 1);
        boost::algorithm::trim(val);
        out[lc_trim(std::move(key))] = std::move(val);
    }
    return out;
}

// Translate an SSDP header map + source IP into the plain-data
// AliveInfo the JSON builder consumes. The JSON shape itself is
// pinned in VirtualSsdpAliveJson.cpp so the contract test can exercise
// it without dragging slicer headers in.
AliveInfo alive_info_from_headers(const std::map<std::string, std::string>& h,
                                  const std::string& bridge_ip) {
    auto get = [&](const char* k) -> std::string {
        auto it = h.find(k);
        return it == h.end() ? std::string() : it->second;
    };
    AliveInfo info;
    info.dev_name     = get("devname.bambu.com");
    info.dev_id       = get("usn");
    info.dev_ip       = bridge_ip;
    info.dev_type     = get("devmodel.bambu.com");
    info.dev_signal   = get("devsignal.bambu.com");
    info.bind_state   = get("devbind.bambu.com");      // builder defaults empty→"free"
    info.sec_link     = get("devseclink.bambu.com");
    info.ssdp_version = get("devversion.bambu.com");
    // connect_type is left empty; builder defaults it to "lan".
    return info;
}

// Parse the host:port out of an SSDP LOCATION header. Bambu printers
// emit a literal IP (no scheme); our bridge emits the same shape. If a
// :PORT is present that's the MQTT port for this device; otherwise the
// caller falls back to 8883 (the LAN-MQTT default).
uint16_t parse_location_port(const std::string& location) {
    // Strip any URL scheme prefix the bridge might have added.
    std::string s = location;
    if (boost::algorithm::starts_with(s, "http://"))  s = s.substr(7);
    if (boost::algorithm::starts_with(s, "https://")) s = s.substr(8);
    auto slash = s.find('/');
    if (slash != std::string::npos) s = s.substr(0, slash);
    auto colon = s.find(':');
    if (colon == std::string::npos) return 0;
    try {
        return static_cast<uint16_t>(std::stoi(s.substr(colon + 1)));
    } catch (...) {
        return 0;
    }
}

bool usn_is_virtual(const std::string& usn) {
    return usn.size() >= 4 && usn.compare(0, 4, "FFFF") == 0;
}

bool is_search_response(const std::string& payload) {
    return payload.size() >= 12 &&
           std::strncmp(payload.data(), "HTTP/1.1 200", 12) == 0;
}

bool is_notify(const std::string& payload) {
    return payload.size() >= 7 &&
           std::strncmp(payload.data(), "NOTIFY ", 7) == 0;
}

// Process-wide dev_id -> advertised MQTT port cache, shared by the
// multicast listener and the unicast probe. Feeds the VirtualMqttClient
// port resolver so per-printer ports resolve with zero manual config.
std::mutex& port_cache_mu() { static std::mutex m; return m; }
std::map<std::string, uint16_t>& port_cache() {
    static std::map<std::string, uint16_t> m;
    return m;
}
void cache_port(const std::string& dev_id, uint16_t port) {
    if (dev_id.empty() || port == 0) return;
    std::lock_guard<std::mutex> lk(port_cache_mu());
    port_cache()[dev_id] = port;
}

// Extract the advertised MQTT port from a parsed SSDP header map: the
// explicit `Bambu-Mqtt-Port` header wins; otherwise fall back to a
// :port embedded in LOCATION (0 if neither is present).
uint16_t mqtt_port_from_headers(std::map<std::string, std::string>& headers) {
    uint16_t port = 0;
    try {
        if (!headers["bambu-mqtt-port"].empty())
            port = static_cast<uint16_t>(std::stoi(headers["bambu-mqtt-port"]));
    } catch (...) { port = 0; }
    if (port == 0)
        port = parse_location_port(headers["location"]);
    return port;
}

} // namespace

// ---------------------------------------------------------------------------

struct VirtualSsdpDiscovery::Impl {
    asio::io_context           io;
    std::unique_ptr<asio::executor_work_guard<asio::io_context::executor_type>> work;
    udp::socket                socket{io};
    udp::endpoint              remote;
    std::array<char, 8192>     buf{};
    std::thread                io_thread;
    std::atomic<bool>          running{false};

    VirtualLanPrinterStore     store;
    // Dedupe + persistence cache. Maps dev_id → most-recently-seen
    // signature so we only re-save when something changed.
    std::map<std::string, std::string> seen;

    asio::steady_timer         probe_timer{io};

    void async_receive() {
        socket.async_receive_from(
            asio::buffer(buf.data(), buf.size()), remote,
            [this](const boost::system::error_code& ec, std::size_t n) {
                if (!running.load()) return;
                if (!ec && n > 0) {
                    std::string payload(buf.data(), buf.data() + n);
                    handle_packet(payload, remote);
                }
                if (running.load()) async_receive();
            });
    }

    // Send the M-SEARCH unicast/multicast probe. We multicast to
    // 239.255.255.250:1900 with ST=bambu so anything implementing the
    // Bambu UPnP profile replies, including bridges.
    void send_msearch() {
        boost::system::error_code ec;
        const std::string body =
            "M-SEARCH * HTTP/1.1\r\n"
            "HOST: 239.255.255.250:1900\r\n"
            "MAN: \"ssdp:discover\"\r\n"
            "MX: 2\r\n"
            "ST: " + std::string(kBambuST) + "\r\n\r\n";
        udp::endpoint mcast(
            asio::ip::make_address(kSsdpMulticastIPv4), kSsdpPort);
        socket.send_to(asio::buffer(body), mcast, 0, ec);
        if (ec) {
            BOOST_LOG_TRIVIAL(warning)
                << "virtual-ssdp: M-SEARCH send failed: " << ec.message();
        } else {
            BOOST_LOG_TRIVIAL(info)
                << "virtual-ssdp: M-SEARCH sent for ST=" << kBambuST;
        }
    }

    void schedule_reprobe() {
        probe_timer.expires_after(std::chrono::seconds(kRepProbeSeconds));
        probe_timer.async_wait(
            [this](const boost::system::error_code& ec) {
                if (ec || !running.load()) return;
                send_msearch();
                schedule_reprobe();
            });
    }

    void handle_packet(const std::string& payload,
                       const udp::endpoint& from) {
        if (!is_search_response(payload) && !is_notify(payload)) return;
        auto headers = parse_headers(payload);
        const std::string usn = headers["usn"];
        if (!usn_is_virtual(usn)) return;

        const std::string bridge_ip = from.address().to_string();

        // Always refresh the live port cache from this advertisement — even
        // when the store dedupe below decides nothing meaningful changed —
        // so the VirtualMqttClient port resolver always has the freshest
        // advertised MQTT port for this dev_id.
        const uint16_t adv_port = mqtt_port_from_headers(headers);
        cache_port(usn, adv_port);

        // Build the alive JSON for DeviceManager.
        const std::string alive_json =
            build_alive_json(alive_info_from_headers(headers, bridge_ip));

        // Dedupe: hash dev_id|ip|name|version → only update store when
        // something meaningful changes.
        const std::string sig =
            usn + "|" + bridge_ip + "|" +
            headers["devname.bambu.com"] + "|" +
            headers["devversion.bambu.com"] + "|" +
            headers["location"];
        bool changed = false;
        auto it = seen.find(usn);
        if (it == seen.end() || it->second != sig) {
            seen[usn] = sig;
            changed = true;
        }

        if (changed) {
            BOOST_LOG_TRIVIAL(info)
                << "virtual-ssdp: discovered dev_id=" << usn
                << " ip=" << bridge_ip
                << " name=" << headers["devname.bambu.com"]
                << " model=" << headers["devmodel.bambu.com"];

            // Persist for next session's hydration.
            VirtualLanPrinterStore::Entry e;
            e.dev_id       = usn;
            e.dev_name     = headers["devname.bambu.com"];
            e.lan_ip       = bridge_ip;
            e.printer_type = headers["devmodel.bambu.com"];
            e.mqtt_port    = adv_port;   // same value cached above
            // SSDP never carries the LAN access code (a secret the user
            // pairs once). Preserve any previously-stored code so
            // re-discovery doesn't wipe it and force re-pairing.
            e.access_code  = "";
            for (const auto& prev : store.load())
                if (prev.dev_id == usn && !prev.access_code.empty()) {
                    e.access_code = prev.access_code;
                    break;
                }
            store.upsert(e);
        }

        // Hand the alive JSON to DeviceManager on the wx main thread.
        // GUI_App might be torn down between now and CallAfter firing;
        // GUI_App::is_closing() guards the dereference there.
        try {
            auto& app = GUI::wxGetApp();
            app.CallAfter([alive_json]() {
                auto& app2 = GUI::wxGetApp();
                if (app2.is_closing()) return;
                if (auto* dm = app2.getDeviceManager()) {
                    dm->on_machine_alive(alive_json);
                }
            });
        } catch (...) {
            // wxGetApp not yet created. Skip; the SSDP listener is only
            // started after on_init_inner builds GUI_App.
        }
    }

    bool open_multicast_socket() {
        boost::system::error_code ec;
        udp::endpoint listen(udp::v4(), kSsdpPort);
        socket.open(udp::v4(), ec);
        if (ec) {
            BOOST_LOG_TRIVIAL(error)
                << "virtual-ssdp: socket open failed: " << ec.message();
            return false;
        }
        socket.set_option(udp::socket::reuse_address(true), ec);
        // SO_REUSEPORT on Linux/macOS: lets us coexist with avahi /
        // the plugin / BambuStudio running side-by-side. Not all
        // boost::asio versions expose this; if reuse_address alone
        // isn't enough we fall back gracefully.
        socket.bind(listen, ec);
        if (ec) {
            BOOST_LOG_TRIVIAL(error)
                << "virtual-ssdp: bind 0.0.0.0:1900 failed: " << ec.message();
            return false;
        }
        socket.set_option(
            asio::ip::multicast::join_group(
                asio::ip::make_address_v4(kSsdpMulticastIPv4)),
            ec);
        if (ec) {
            BOOST_LOG_TRIVIAL(warning)
                << "virtual-ssdp: join_group failed: " << ec.message();
            // Non-fatal; on some hosts the JOIN fails but unicast
            // replies still arrive.
        }
        socket.set_option(
            asio::ip::multicast::enable_loopback(true), ec);
        return true;
    }

    void hydrate_from_store() {
        auto rows = store.load();
        if (rows.empty()) return;
        for (const auto& e : rows) {
            // Build an alive JSON from the persisted record so the
            // device list shows up before any SSDP traffic arrives.
            AliveInfo info;
            info.dev_name  = e.dev_name;
            info.dev_id    = e.dev_id;
            info.dev_ip    = e.lan_ip;
            info.dev_type  = e.printer_type;
            // dev_signal/connect_type/bind_state left empty: builder
            // defaults connect_type→"lan", bind_state→"free".
            const std::string alive_json = build_alive_json(info);
            try {
                auto& app = GUI::wxGetApp();
                app.CallAfter([alive_json]() {
                    auto& app2 = GUI::wxGetApp();
                    if (app2.is_closing()) return;
                    if (auto* dm = app2.getDeviceManager()) {
                        dm->on_machine_alive(alive_json);
                    }
                });
            } catch (...) {
            }
        }
        BOOST_LOG_TRIVIAL(info)
            << "virtual-ssdp: hydrated " << rows.size()
            << " entries from persistent store";
    }
};

VirtualSsdpDiscovery::VirtualSsdpDiscovery() : m_impl(std::make_unique<Impl>()) {}

VirtualSsdpDiscovery::~VirtualSsdpDiscovery() {
    stop();
}

void VirtualSsdpDiscovery::start() {
    if (!m_impl) return;
    if (m_impl->running.exchange(true)) return;

    m_impl->hydrate_from_store();

    if (!m_impl->open_multicast_socket()) {
        // Bind failed (port 1900 owned by another process etc.). Keep
        // the persisted entries visible; the listener just won't catch
        // live updates this run. Mark not-running so stop() is a no-op.
        m_impl->running.store(false);
        return;
    }

    m_impl->work.reset(new asio::executor_work_guard<asio::io_context::executor_type>(
        m_impl->io.get_executor()));
    m_impl->io_thread = std::thread([this] {
        try {
            m_impl->io.run();
        } catch (const std::exception& ex) {
            BOOST_LOG_TRIVIAL(error)
                << "virtual-ssdp: io thread crashed: " << ex.what();
        }
    });

    m_impl->async_receive();
    m_impl->send_msearch();
    m_impl->schedule_reprobe();
    BOOST_LOG_TRIVIAL(info) << "virtual-ssdp: listener up";
}

void VirtualSsdpDiscovery::stop() {
    if (!m_impl) return;
    if (!m_impl->running.exchange(false)) return;
    boost::system::error_code ec;
    m_impl->probe_timer.cancel(ec);
    m_impl->socket.close(ec);
    m_impl->work.reset();
    m_impl->io.stop();
    if (m_impl->io_thread.joinable()) m_impl->io_thread.join();
    BOOST_LOG_TRIVIAL(info) << "virtual-ssdp: listener down";
}

uint16_t VirtualSsdpDiscovery::advertised_port(const std::string& dev_id) {
    std::lock_guard<std::mutex> lk(port_cache_mu());
    auto it = port_cache().find(dev_id);
    return it == port_cache().end() ? 0 : it->second;
}

uint16_t VirtualSsdpDiscovery::probe_port(const std::string& bridge_ip,
                                          const std::string& dev_id,
                                          int timeout_ms) {
    if (bridge_ip.empty() || dev_id.empty()) return 0;
    // Already learned it (live listener or a prior probe)? Skip the network.
    if (uint16_t cached = advertised_port(dev_id)) return cached;

    uint16_t found = 0;
    try {
        boost::system::error_code ec;
        const auto addr = asio::ip::make_address(bridge_ip, ec);
        if (ec) return 0;

        asio::io_context io;
        udp::socket sock(io, udp::endpoint(udp::v4(), 0));
        const std::string body =
            "M-SEARCH * HTTP/1.1\r\n"
            "HOST: " + bridge_ip + ":" + std::to_string(kSsdpPort) + "\r\n"
            "MAN: \"ssdp:discover\"\r\n"
            "MX: 1\r\n"
            "ST: " + std::string(kBambuST) + "\r\n\r\n";
        sock.send_to(asio::buffer(body), udp::endpoint(addr, kSsdpPort), 0, ec);
        if (ec) return 0;

        // Read replies until we find dev_id or the timeout elapses, caching
        // every advertised port we see along the way (one probe warms the
        // cache for all of the bridge's printers).
        std::array<char, 8192> rbuf{};
        udp::endpoint          from;
        std::function<void()>  do_recv;
        do_recv = [&]() {
            sock.async_receive_from(
                asio::buffer(rbuf), from,
                [&](const boost::system::error_code& rec_ec, std::size_t n) {
                    if (rec_ec || n == 0) return;        // stop: no more work
                    std::string pkt(rbuf.data(), rbuf.data() + n);
                    auto h = parse_headers(pkt);
                    const std::string u = h["usn"];
                    if (usn_is_virtual(u)) {
                        const uint16_t p = mqtt_port_from_headers(h);
                        cache_port(u, p);
                        if (p && u == dev_id) { found = p; return; }  // done
                    }
                    do_recv();                            // keep listening
                });
        };
        do_recv();
        io.run_for(std::chrono::milliseconds(timeout_ms));
    } catch (...) { /* best-effort: fall through to whatever we cached */ }

    return found ? found : advertised_port(dev_id);
}

uint16_t VirtualSsdpDiscovery::resolve_mqtt_port(const std::string& dev_id,
                                                 const std::string& bridge_ip_hint) {
    // Resolution order:
    //   1. live SSDP cache       (freshest — set by the running listener)
    //   2. unicast SSDP probe    (preferred over the persisted store: the
    //                             bridge's port assignment can change between
    //                             sessions — printer reordering, port-offset
    //                             rotation, Windows host with multicast
    //                             filtered out — and the persisted port goes
    //                             stale silently. A unicast M-SEARCH costs
    //                             ~800ms worst-case but only fires when the
    //                             live cache is cold, and warms the cache
    //                             for every printer on the bridge from one
    //                             round-trip.)
    //   3. persisted store port  (last resort: the probe failed/timed out;
    //                             stale port beats giving up entirely, and
    //                             the connect failure that follows will be
    //                             handled by VirtualMqttClient's retry path.)
    if (uint16_t p = advertised_port(dev_id)) {
        BBL_LOG("virtual-ssdp", "port_resolved")
            .str("dev_id", dev_id).num("port", p).str("source", "ssdp_cache");
        return p;
    }

    // Find the bridge IP to probe — from the caller's hint or the store.
    std::string ip = bridge_ip_hint;
    uint16_t    persisted_port = 0;
    {
        VirtualLanPrinterStore store;
        for (const auto& e : store.load()) {
            if (e.dev_id == dev_id) {
                persisted_port = e.mqtt_port;
                if (ip.empty()) ip = e.lan_ip;
                break;
            }
        }
    }

    // Unicast probe of the bridge host — reliable where multicast is dropped
    // (Windows Firewall, segmented networks, hyper-V/WSL bridges).
    if (!ip.empty()) {
        if (uint16_t p = probe_port(ip, dev_id)) {
            BBL_LOG("virtual-ssdp", "port_resolved")
                .str("dev_id", dev_id).num("port", p).str("source", "unicast_probe");
            return p;
        }
    }

    // Last resort — persisted port. May be stale; the connect path's failure
    // handling is the user's signal to re-probe / re-pair.
    if (persisted_port) {
        BBL_LOG("virtual-ssdp", "port_resolved")
            .str("dev_id", dev_id).num("port", persisted_port)
            .str("source", "persisted_store").str("note", "probe_failed_or_no_ip");
        return persisted_port;
    }

    BBL_LOG("virtual-ssdp", "port_resolved")
        .str("dev_id", dev_id).num("port", 0)
        .str("source", "none").str("err", "not_found");
    return 0;
}

uint16_t VirtualSsdpDiscovery::port_for(const std::string& dev_id,
                                        uint16_t           port_base,
                                        const std::string& bridge_ip_hint) {
    constexpr uint16_t kMqttBase = 8883;
    uint16_t mp = resolve_mqtt_port(dev_id, bridge_ip_hint);
    if (mp == 0) mp = kMqttBase;   // unknown dev -> index 0 (base port)
    const uint16_t resolved =
        static_cast<uint16_t>(int(port_base) + (int(mp) - int(kMqttBase)));
    BBL_LOG("virtual-ssdp", "port_for")
        .str("dev_id",      dev_id)
        .num("port_base",   port_base)
        .num("mqtt_port",   mp)
        .num("resolved",    resolved);
    return resolved;
}

} // namespace Slic3r
