// VirtualSsdpDiscovery implementation. See header for design.

#include "VirtualSsdpDiscovery.hpp"

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
#include <map>
#include <memory>
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
            e.access_code  = "";   // unknown until user pairs
            e.printer_type = headers["devmodel.bambu.com"];
            // Explicit Bambu-Mqtt-Port header wins; LOCATION is bare-IP in
            // the bridge's A1-mimicry mode so parse_location_port returns 0
            // there. Keep the LOCATION fallback for any future bridge build
            // that does embed :port (and for unit-test fixtures).
            try {
                if (!headers["bambu-mqtt-port"].empty())
                    e.mqtt_port = static_cast<uint16_t>(std::stoi(headers["bambu-mqtt-port"]));
            } catch (...) { e.mqtt_port = 0; }
            if (e.mqtt_port == 0)
                e.mqtt_port = parse_location_port(headers["location"]);
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

} // namespace Slic3r
