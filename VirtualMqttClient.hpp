// VirtualMqttClient — open-source MQTT-over-TLS client for the
// virtual-Bambu-printer path inside the slicer.
//
// Background: the proprietary `bambu_networking` plugin is the only
// thing in BambuStudio that knows how to talk MQTT-over-TLS to a Bambu
// printer. It validates server certs against `slicer_base64.cer`
// (Bambu's CA). The Bambu Bridge mints its own self-signed certs that
// can't possibly chain to Bambu's CA — so the plugin rejects bridge
// connections with `tlsv1 alert unknown ca`.
//
// To work around that without forking the plugin (or fooling crypto),
// `NetworkAgent` looks at the dev_id of every LAN-MQTT call. If the
// dev_id matches `NetworkAgent::kVirtualDevIdPrefix` (currently
// "FFFF"), NetworkAgent dispatches the call here instead of into the
// plugin. This client speaks the same Bambu MQTT wire format the
// printer expects, but with `verify=false` on the TLS context, so the
// bridge's self-signed cert is accepted.
//
// Real (non-virtual) printers continue to go through the plugin
// completely unchanged.
//
// Scope:
//   - LAN MQTT only. Bridge is the wire target; the wire format is
//     identical to what a real Bambu printer would speak.
//   - One TCP / TLS / MQTT session per virtual dev_id. The bridge's
//     existing per-device MqttBroker accepts multiple concurrent
//     virtual sessions on different per-device ports already; this
//     client matches that model (one Session per dev_id, with its own
//     I/O thread).
//   - Subscribes to `device/<dev_id>/report` on CONNACK so push
//     status from the printer flows through immediately.
//
// Threading:
//   - One per-Session I/O thread reading the SSL socket. Decodes
//     incoming MQTT packets and either dispatches to the user-set
//     callbacks (PUBLISH → OnMessage; CONNACK rc=0 → OnLocalConnected)
//     or replies (PINGREQ → PINGRESP isn't strictly needed for the
//     client; we don't emit PINGREQ either — slicer activity provides
//     keepalive).
//   - Public API is thread-safe; an internal mutex serialises
//     map-of-sessions mutations.
//
// Linux-only for the first iteration. Same scope as the bridge.

#ifndef SLIC3R_VIRTUAL_MQTT_CLIENT_HPP
#define SLIC3R_VIRTUAL_MQTT_CLIENT_HPP

#include <atomic>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>

namespace Slic3r {

// Callback typedefs are mirrored from the slicer's bambu_networking.hpp.
// Re-declaring an identical typedef in the same namespace is legal and
// keeps this header standalone-buildable without dragging the slicer's
// NetworkAgent surface into the shared library. When the consuming
// slicer also pulls in bambu_networking.hpp the two declarations refer
// to the same type and coexist cleanly.
#ifndef SLIC3R_BAMBU_NETWORKING_CALLBACKS_DECLARED
#define SLIC3R_BAMBU_NETWORKING_CALLBACKS_DECLARED
typedef std::function<void(int status, std::string dev_id, std::string msg)> OnLocalConnectedFn;
typedef std::function<void(std::string dev_id, std::string msg)>             OnMessageFn;
#endif

class VirtualMqttClient {
public:
    // Per-process singleton, lazily constructed. Stored in a free
    // function-local static so destruction order is deterministic on
    // exit (after every NetworkAgent has dropped its reference).
    static VirtualMqttClient& instance();

    VirtualMqttClient();
    ~VirtualMqttClient();

    VirtualMqttClient(const VirtualMqttClient&)            = delete;
    VirtualMqttClient& operator=(const VirtualMqttClient&) = delete;

    // Open a new TLS/MQTT session for `dev_id` to `host`:`port` with
    // username "bblp" and password = access_code. Idempotent — if a
    // session for `dev_id` already exists, returns success without
    // re-opening. The port is resolved via the registered resolver
    // (see set_port_resolver), falling back to 8883 if no resolver is
    // set or the resolver returns 0. Returns 0 on success, negative on
    // failure.
    int connect_printer(std::string dev_id,
                        std::string host,
                        std::string access_code);

    // Register a callback that maps a (possibly virtual `FFFF…`)
    // dev_id to the bridge's MQTT port for that printer. The in-GUI
    // BridgeApp owns the authoritative port assignments; GUI_App
    // installs this resolver after construction so the slicer can
    // connect to the right port even though the slicer's MachineObject
    // only stores `dev_ip` (not port). Returning 0 means "no entry";
    // the client falls back to 8883.
    using PortResolverFn = std::function<uint16_t(const std::string&)>;
    void set_port_resolver(PortResolverFn fn);

    // Tear down the session for `dev_id`. Safe to call when no
    // session exists. Returns 0 on success.
    int disconnect_printer(std::string dev_id);

    // Publish a raw JSON payload to `device/<dev_id>/request` at the
    // given QoS. Returns 0 on success, negative on error (no session,
    // socket closed, encode failure).
    int send_message(std::string dev_id, std::string json, int qos);

    // Install the captured callbacks. NetworkAgent calls these with
    // whatever the slicer registered via set_on_local_*_fn. We fire
    // them from the per-Session I/O thread.
    void set_on_message       (OnMessageFn        fn);
    void set_on_local_connect (OnLocalConnectedFn fn);

private:
    struct Session;

    // Owns the OpenSSL SSL_CTX. We use a single ctx for all sessions
    // (TLS 1.2+, verify=false, no client cert).
    void* m_ssl_ctx = nullptr;   // SSL_CTX* — kept void* in header to
                                 //   avoid leaking <openssl/ssl.h>
                                 //   into includers.

    mutable std::mutex                                m_mu;
    std::map<std::string, std::unique_ptr<Session>>   m_sessions;
    OnMessageFn                                       m_on_message;
    OnLocalConnectedFn                                m_on_local_connect;
    PortResolverFn                                    m_port_resolver;

    // Internal helpers run on the I/O thread.
    static void session_loop(VirtualMqttClient* self,
                             Session*           sess);

    // SSL_CTX init. Called from the ctor.
    void init_ssl_ctx();
};

} // namespace Slic3r

#endif // SLIC3R_VIRTUAL_MQTT_CLIENT_HPP
