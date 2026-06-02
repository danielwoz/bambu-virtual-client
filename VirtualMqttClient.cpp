// VirtualMqttClient implementation. See header for design rationale.
//
// Networking: boost::asio for TCP + DNS resolve. TLS: raw OpenSSL
// (TLS 1.2, verify=false) on top of the asio socket's native_handle().
// The asio socket's fd is release()d into SSL_set_fd so the rest of
// the SSL_read/SSL_write logic (and the session I/O loop) remains
// unchanged. This makes the module compile on Windows where
// <sys/socket.h>/<netdb.h>/<arpa/inet.h> aren't available.

#include "VirtualMqttClient.hpp"

#include "MqttFraming.hpp"
#include "StructuredLog.hpp"           // BBL_LOG — env-gated JSONL diagnostics
#include "VirtualSsdpDiscovery.hpp"   // unicast port probe for cold-cache connects

#include <array>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <thread>
#include <vector>

#include <boost/asio.hpp>
#include <boost/system/error_code.hpp>

#ifdef _WIN32
#  include <winsock2.h>
#  include <ws2tcpip.h>
#else
#  include <signal.h>
#  include <sys/socket.h>
#  include <unistd.h>
#endif

#include <mutex>

#include <openssl/err.h>
#include <openssl/ssl.h>

namespace Slic3r {

namespace {

namespace mqtt = ::Slic3r::virtual_mqtt;
namespace asio = boost::asio;
using asio::ip::tcp;
using boost::system::error_code;

// MQTT 3.1.1 control-packet types (high nibble of the fixed header).
constexpr uint8_t MQTT_CONNECT   = 0x10;
constexpr uint8_t MQTT_SUBSCRIBE = 0x82; // qos=1 control flags
constexpr uint8_t MQTT_PINGREQ   = 0xC0;
constexpr uint8_t MQTT_DISCONNECT = 0xE0;

void encode_remaining_length(std::vector<uint8_t>& out, std::size_t len) {
    do {
        uint8_t b = len & 0x7F;
        len >>= 7;
        if (len) b |= 0x80;
        out.push_back(b);
    } while (len);
}

void encode_string(std::vector<uint8_t>& out, const std::string& s) {
    out.push_back(static_cast<uint8_t>((s.size() >> 8) & 0xFF));
    out.push_back(static_cast<uint8_t>(s.size() & 0xFF));
    out.insert(out.end(), s.begin(), s.end());
}

// MQTT 3.1.1 CONNECT packet. Mirrors what BambuStudio's plugin sends
// for LAN MQTT (username "bblp", password = access code, clean_session
// = true, keep_alive = 60).
std::vector<uint8_t> encode_connect(const std::string& client_id,
                                    const std::string& username,
                                    const std::string& password)
{
    std::vector<uint8_t> payload;
    // Protocol name "MQTT"
    encode_string(payload, std::string("MQTT"));
    // Protocol level
    payload.push_back(0x04);
    // Connect flags: clean_session(1) | password(1) | username(1)
    payload.push_back(0x02 | 0x40 | 0x80);
    // Keep-alive seconds (big-endian)
    payload.push_back(0x00);
    payload.push_back(0x3C); // 60
    // Client ID
    encode_string(payload, client_id);
    // Username
    encode_string(payload, username);
    // Password
    encode_string(payload, password);

    std::vector<uint8_t> pkt;
    pkt.push_back(MQTT_CONNECT);
    encode_remaining_length(pkt, payload.size());
    pkt.insert(pkt.end(), payload.begin(), payload.end());
    return pkt;
}

// MQTT 3.1.1 SUBSCRIBE with one topic filter at the given QoS.
std::vector<uint8_t> encode_subscribe(uint16_t packet_id,
                                      const std::string& topic,
                                      uint8_t qos)
{
    std::vector<uint8_t> payload;
    payload.push_back(static_cast<uint8_t>((packet_id >> 8) & 0xFF));
    payload.push_back(static_cast<uint8_t>(packet_id & 0xFF));
    encode_string(payload, topic);
    payload.push_back(qos);

    std::vector<uint8_t> pkt;
    pkt.push_back(MQTT_SUBSCRIBE);
    encode_remaining_length(pkt, payload.size());
    pkt.insert(pkt.end(), payload.begin(), payload.end());
    return pkt;
}

std::vector<uint8_t> encode_disconnect()
{
    return { MQTT_DISCONNECT, 0x00 };
}

// Open a TCP socket to host:port via boost::asio. Returns the released
// native socket fd, or -1 on failure. The asio socket is release()d so
// the fd's lifetime is owned by the caller (handed to OpenSSL via
// SSL_set_fd). Synchronous — runs on the caller's thread.
int tcp_connect(const std::string& host, uint16_t port) {
    try {
        asio::io_context io;
        tcp::resolver resolver(io);
        error_code ec;
        auto endpoints = resolver.resolve(host, std::to_string(port), ec);
        if (ec) return -1;
        tcp::socket sock(io);
        asio::connect(sock, endpoints, ec);
        if (ec) return -1;
        auto native = sock.native_handle();
        error_code rel_ec;
        sock.release(rel_ec);
        return static_cast<int>(native);
    } catch (const std::exception&) {
        return -1;
    }
}

// Cross-platform fd close. The fd we manage was obtained via
// tcp::socket::release(), so it owns the system socket — close it the
// way the platform expects.
inline void close_fd(int fd) {
    if (fd < 0) return;
#ifdef _WIN32
    ::closesocket(fd);
#else
    ::close(fd);
#endif
}

// Cross-platform half-close. Called before close_fd to unblock any
// in-flight SSL_read on the I/O thread.
inline void shutdown_fd(int fd) {
    if (fd < 0) return;
#ifdef _WIN32
    ::shutdown(fd, SD_BOTH);
#else
    ::shutdown(fd, SHUT_RDWR);
#endif
}

// Sleep for ms milliseconds — portable across POSIX and Windows
// (avoids ::usleep which is POSIX-only).
inline void sleep_ms(int ms) {
    std::this_thread::sleep_for(std::chrono::milliseconds(ms));
}

#ifndef _WIN32
// OpenSSL's SSL_write ultimately calls ::send/::write on the underlying
// fd. When the peer has already closed (the broker half-closes mid-
// teardown), the kernel raises SIGPIPE on the writer. We never pass
// MSG_NOSIGNAL (SSL_write doesn't expose send-flags), so an unprepared
// host application gets killed.
//
// Fix: install SIG_IGN for SIGPIPE on first connect, but only if the
// current handler is still SIG_DFL — never clobber a user-installed
// handler. Uses sigaction(2), not signal(2), to avoid the latter's
// buggy POSIX semantics around SA_RESTART.
inline void install_sigpipe_ignore_once() {
    static std::once_flag once;
    std::call_once(once, []() {
        struct sigaction current{};
        if (sigaction(SIGPIPE, nullptr, &current) == 0 &&
            current.sa_handler == SIG_DFL) {
            struct sigaction sa{};
            sa.sa_handler = SIG_IGN;
            sigemptyset(&sa.sa_mask);
            sigaction(SIGPIPE, &sa, nullptr);
        }
    });
}
#endif

} // namespace

// ---------------------------------------------------------------------------
// Session — one per dev_id.
// ---------------------------------------------------------------------------

struct VirtualMqttClient::Session {
    std::string         dev_id;
    std::string         host;
    uint16_t            port         = 8883;
    std::string         access_code;
    int                 fd           = -1;
    SSL*                ssl          = nullptr;
    std::atomic<bool>   stopped{false};
    std::thread         io_thread;
    // Serialises SSL_write calls — the I/O thread reads, public-API
    // calls write. OpenSSL SSL objects are not thread-safe.
    std::mutex          write_mu;
};

// ---------------------------------------------------------------------------
// Singleton + lifecycle
// ---------------------------------------------------------------------------

VirtualMqttClient& VirtualMqttClient::instance() {
    static VirtualMqttClient g;
    return g;
}

VirtualMqttClient::VirtualMqttClient() {
    init_ssl_ctx();
}

VirtualMqttClient::~VirtualMqttClient() {
    // Snapshot keys under lock, then tear each session down outside it
    // (disconnect_printer takes the lock itself).
    std::vector<std::string> ids;
    {
        std::lock_guard<std::mutex> lk(m_mu);
        ids.reserve(m_sessions.size());
        for (auto& kv : m_sessions) ids.push_back(kv.first);
    }
    for (auto& id : ids) disconnect_printer(id);
    if (m_ssl_ctx) {
        SSL_CTX_free(static_cast<SSL_CTX*>(m_ssl_ctx));
        m_ssl_ctx = nullptr;
    }
}

void VirtualMqttClient::init_ssl_ctx() {
    // OpenSSL initialisation. CurlGlobalInit may have already done
    // SSL_library_init / OpenSSL_add_all_algorithms — both are
    // idempotent on the OpenSSL we link.
    static std::once_flag init_once;
    std::call_once(init_once, []() {
        SSL_load_error_strings();
        OpenSSL_add_ssl_algorithms();
    });

    SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        return;
    }
    // verify = false. The bridge presents a self-signed cert; we
    // accept it. The point of this client is to bypass the plugin's
    // strict Bambu-CA-chain validation.
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nullptr);
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    m_ssl_ctx = ctx;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

void VirtualMqttClient::set_on_message(OnMessageFn fn) {
    std::lock_guard<std::mutex> lk(m_mu);
    m_on_message = std::move(fn);
}

void VirtualMqttClient::set_on_local_connect(OnLocalConnectedFn fn) {
    std::lock_guard<std::mutex> lk(m_mu);
    m_on_local_connect = std::move(fn);
}

void VirtualMqttClient::set_port_resolver(PortResolverFn fn) {
    std::lock_guard<std::mutex> lk(m_mu);
    m_port_resolver = std::move(fn);
}

int VirtualMqttClient::connect_printer(std::string dev_id,
                                       std::string host,
                                       std::string access_code) {
#ifndef _WIN32
    // SSL_write paths in this client can raise SIGPIPE when the broker
    // half-closes mid-teardown. Ignore SIGPIPE process-wide on first
    // connect (but only if the host hasn't already installed its own
    // handler).
    install_sigpipe_ignore_once();
#endif

    PortResolverFn resolver;
    {
        std::lock_guard<std::mutex> lk(m_mu);
        if (m_sessions.count(dev_id)) {
            return 0; // already connected
        }
        resolver = m_port_resolver;
    }

    if (!m_ssl_ctx) {
        return -1;
    }

    // Resolve the MQTT port. BridgeApp assigns one port per virtual
    // device (mqtt_port_base + index); the slicer's MachineObject only
    // holds `dev_ip` so we look up the port through the resolver
    // GUI_App installed at startup. Falls back to 8883 when the
    // resolver is missing or doesn't know the dev_id (matches real
    // Bambu LAN MQTT behaviour).
    uint16_t port = 0;
    if (resolver) port = resolver(dev_id);
    // Resolver came up empty (cold SSDP cache, no persisted port, multicast
    // SSDP dropped by a host firewall). We DO know `host` — the exact bridge
    // IP we're about to dial — so probe it directly by UNICAST M-SEARCH for
    // this dev's advertised Bambu-Mqtt-Port. Reliable where multicast isn't,
    // and needs no persisted state.
    if (port == 0) port = VirtualSsdpDiscovery::probe_port(host, dev_id);
    if (port == 0) port = 8883;
    std::fprintf(stderr,
        "[virtual-mqtt] connect dev=%s host=%s -> port=%u\n",
        dev_id.c_str(), host.c_str(), static_cast<unsigned>(port));
    std::fflush(stderr);
    BBL_LOG("virtual-mqtt", "connect_begin")
        .str("dev_id", dev_id)
        .str("host",   host)
        .num("port",   port);

    // Try the initial TCP+TLS handshake. If it fails because the bridge
    // isn't listening yet (the common case during slicer startup before
    // the in-GUI bridge has opened its MQTT broker on `port`), we still
    // register the session and let the io_thread's reopen_tls + backoff
    // loop bring it up later. Without this, an ECONNREFUSED at the
    // hydration-driven first connect would leave the session permanently
    // un-established and every send_message would log "no session".
    int  fd  = tcp_connect(host, port);
    SSL* ssl = nullptr;
    if (fd < 0) {
    } else {
        ssl = SSL_new(static_cast<SSL_CTX*>(m_ssl_ctx));
        if (!ssl) {
            close_fd(fd);
            fd = -1;
        } else {
            SSL_set_fd(ssl, fd);
            int rc = SSL_connect(ssl);
            if (rc != 1) {
                const int  ssl_err = SSL_get_error(ssl, rc);
                const auto err_q   = ERR_get_error();
                SSL_free(ssl);
                ssl = nullptr;
                close_fd(fd);
                fd = -1;
            }
        }
    }

    auto sess         = std::make_unique<Session>();
    sess->dev_id      = dev_id;
    sess->host        = std::move(host);
    sess->port        = port;
    sess->access_code = access_code;
    sess->fd          = fd;
    sess->ssl         = ssl;

    Session* raw = sess.get();
    {
        std::lock_guard<std::mutex> lk(m_mu);
        m_sessions[dev_id] = std::move(sess);
    }
    raw->io_thread = std::thread(session_loop, this, raw);
    BBL_LOG("virtual-mqtt", "connect_result")
        .str("dev_id",  raw->dev_id)
        .num("port",    raw->port)
        .boolean("tcp_ok", raw->fd  >= 0)
        .boolean("tls_ok", raw->ssl != nullptr)
        .num("rc",      0);
    return 0;
}

int VirtualMqttClient::disconnect_printer(std::string dev_id) {
    std::unique_ptr<Session> doomed;
    {
        std::lock_guard<std::mutex> lk(m_mu);
        auto it = m_sessions.find(dev_id);
        if (it == m_sessions.end()) return 0;
        doomed = std::move(it->second);
        m_sessions.erase(it);
    }
    // Politely send DISCONNECT before tearing down.
    if (doomed->ssl) {
        std::lock_guard<std::mutex> lk(doomed->write_mu);
        auto pkt = encode_disconnect();
        SSL_write(doomed->ssl, pkt.data(), static_cast<int>(pkt.size()));
    }
    // Teardown order matters: the I/O thread is in SSL_read(ssl, ...). We
    // must NOT free the SSL* (or close the fd) while another thread is
    // inside SSL_read — that's a use-after-free. Sequence:
    //   1) signal stop so the loop exits on the next iteration,
    //   2) shutdown the socket to force any in-flight SSL_read to return
    //      an error and unblock the loop,
    //   3) join the I/O thread — only then is it safe to touch ssl/fd,
    //   4) free SSL and close fd.
    doomed->stopped.store(true);
    if (doomed->fd >= 0)
        shutdown_fd(doomed->fd);
    if (doomed->io_thread.joinable())
        doomed->io_thread.join();
    if (doomed->ssl) {
        SSL_shutdown(doomed->ssl);
        SSL_free(doomed->ssl);
        doomed->ssl = nullptr;
    }
    if (doomed->fd >= 0) {
        close_fd(doomed->fd);
        doomed->fd = -1;
    }
    return 0;
}

int VirtualMqttClient::send_message(std::string dev_id,
                                    std::string json,
                                    int qos) {
    Session* sess = nullptr;
    {
        std::lock_guard<std::mutex> lk(m_mu);
        auto it = m_sessions.find(dev_id);
        if (it == m_sessions.end()) {
            BBL_LOG("virtual-mqtt", "publish_send")
                .str("dev_id", dev_id)
                .num("qos",    qos)
                .num("bytes",  json.size())
                .str("err",    "no_session")
                .num("rc",     -1);
            return -1;
        }
        sess = it->second.get();
    }

    const std::string topic = "device/" + dev_id + "/request";
    auto pkt = mqtt::encode_publish(topic,
                                    std::vector<uint8_t>(json.begin(),
                                                         json.end()),
                                    static_cast<uint8_t>(qos),
                                    /*retain=*/false,
                                    /*packet_id=*/0,
                                    /*dup=*/false);

    std::lock_guard<std::mutex> wlk(sess->write_mu);
    if (!sess->ssl) {
        // Session loop is between reconnect attempts; the SSL pointer is
        // momentarily null. Drop the message rather than crashing. The
        // slicer's state machine retries push_status frequently — the
        // next attempt after CONNACK will go through.
        BBL_LOG("virtual-mqtt", "publish_send")
            .str("dev_id", dev_id)
            .str("topic",  topic)
            .num("qos",    qos)
            .num("bytes",  json.size())
            .str("err",    "ssl_null_reconnect_window")
            .num("rc",     -1);
        return -1;
    }
    int n = SSL_write(sess->ssl, pkt.data(), static_cast<int>(pkt.size()));
    const bool wrote_all = (n == static_cast<int>(pkt.size()));
    BBL_LOG("virtual-mqtt", "publish_send")
        .str("dev_id", dev_id)
        .str("topic",  topic)
        .num("qos",    qos)
        .num("bytes",  json.size())
        // First 16 bytes of the JSON payload, hex — handy for cross-correlating
        // against the bridge log without leaking sensitive content.
        .bytes_prefix_hex("payload_hex", json.data(), json.size(), 16)
        .num("ssl_write_n", n)
        .num("rc", wrote_all ? 0 : -1);
    if (!wrote_all) {
        return -1;
    }
    return 0;
}

// ---------------------------------------------------------------------------
// I/O thread
// ---------------------------------------------------------------------------

void VirtualMqttClient::session_loop(VirtualMqttClient* self,
                                     Session*           sess) {
    auto fire_on_connect = [&](int rc) {
        OnLocalConnectedFn cb;
        {
            std::lock_guard<std::mutex> lk(self->m_mu);
            cb = self->m_on_local_connect;
        }
        if (cb) {
            // Plugin's OnLocalConnectedFn signature is
            // (int status, std::string dev_id, std::string msg).
            cb(rc, sess->dev_id, std::string());
        }
    };
    auto fire_on_message = [&](const std::string& topic_unused,
                               std::vector<uint8_t> payload) {
        (void) topic_unused; // dev_id is what the slicer routes on
        OnMessageFn cb;
        {
            std::lock_guard<std::mutex> lk(self->m_mu);
            cb = self->m_on_message;
        }
        BBL_LOG("virtual-mqtt", "publish_recv")
            .str("dev_id", sess->dev_id)
            .str("topic",  topic_unused)
            .num("bytes",  payload.size())
            .bytes_prefix_hex("payload_hex",
                              payload.data(), payload.size(), 16)
            .boolean("delivered_to_cb", cb != nullptr);
        if (cb) {
            std::string msg(payload.begin(), payload.end());
            cb(sess->dev_id, msg);
        }
    };

    // Re-open TCP + TLS. Called when the I/O loop exits unexpectedly
    // (bridge restart, network blip). Mirrors connect_printer's open
    // sequence. Takes write_mu while swapping the SSL pointer so
    // send_message can't race against the swap.
    auto reopen_tls = [&]() -> bool {
        int new_fd = tcp_connect(sess->host, sess->port);
        if (new_fd < 0) return false;
        SSL* new_ssl = SSL_new(static_cast<SSL_CTX*>(self->m_ssl_ctx));
        if (!new_ssl) { close_fd(new_fd); return false; }
        SSL_set_fd(new_ssl, new_fd);
        if (SSL_connect(new_ssl) != 1) {
            SSL_free(new_ssl);
            close_fd(new_fd);
            return false;
        }
        // Publish to Session under write_mu (send_message also takes it).
        std::lock_guard<std::mutex> wlk(sess->write_mu);
        sess->fd  = new_fd;
        sess->ssl = new_ssl;
        return true;
    };

    auto send_connect = [&]() -> bool {
        std::lock_guard<std::mutex> wlk(sess->write_mu);
        const std::string client_id = "virtual-" + sess->dev_id;
        auto pkt = encode_connect(client_id,
                                  /*username=*/"bblp",
                                  sess->access_code);
        if (!sess->ssl) return false;
        return SSL_write(sess->ssl, pkt.data(),
                         static_cast<int>(pkt.size())) > 0;
    };

    // Subscribe to device/<dev_id>/report once CONNACK comes back.
    auto send_subscribe = [&]() {
        const std::string topic = "device/" + sess->dev_id + "/report";
        auto pkt = encode_subscribe(/*packet_id=*/1, topic, /*qos=*/0);
        std::lock_guard<std::mutex> wlk(sess->write_mu);
        if (sess->ssl)
            SSL_write(sess->ssl, pkt.data(), static_cast<int>(pkt.size()));
    };

    int  backoff_s        = 1;
    bool first_attempt    = true;

    while (!sess->stopped.load()) {
        // On entry: connect_printer() has already opened fd+ssl for the
        // FIRST attempt. On subsequent iterations (reconnects after
        // session death), we re-open here.
        if (!first_attempt) {
            for (int i = 0; i < backoff_s * 10; ++i) {
                if (sess->stopped.load()) return;
                sleep_ms(100); // 100 ms slices for prompt stop
            }
            if (sess->stopped.load()) return;
            if (!reopen_tls()) {
                backoff_s = std::min(backoff_s * 2, 30);
                continue;
            }
        }
        first_attempt = false;

        if (!send_connect()) {
            // fall through to read loop; it'll exit immediately on
            // SSL_read error, then we backoff.
        }

        // Inner read loop — runs until socket dies or stop signalled.
        std::vector<uint8_t> rbuf;
        bool connack_seen = false;
        while (!sess->stopped.load()) {
            std::array<uint8_t, 4096> buf{};
            // Capture ssl under nothing — we control its lifetime; while
            // this thread is alive, only disconnect_printer can free it
            // (and disconnect_printer joins us first).
            SSL* ssl_now = sess->ssl;
            if (!ssl_now) break;
            int n = SSL_read(ssl_now, buf.data(),
                             static_cast<int>(buf.size()));
            if (n <= 0) {
                const int err = SSL_get_error(ssl_now, n);
                if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
                    continue;
                break;
            }
            rbuf.insert(rbuf.end(), buf.data(), buf.data() + n);

            for (;;) {
                auto pk = mqtt::decode_packet(rbuf.data(), rbuf.size());
                if (!pk) break;
                if (pk->error != mqtt::DecodeError::Ok) {
                    rbuf.clear();
                    // Drop the read loop; outer loop will reconnect.
                    goto read_loop_exit;
                }
                switch (pk->type) {
                case mqtt::PacketType::Connack: {
                    connack_seen = true;
                    backoff_s    = 1; // reset on a healthy CONNACK
                    fire_on_connect(/*rc=*/0);
                    send_subscribe();
                    break;
                }
                case mqtt::PacketType::Publish: {
                    const auto& pl = pk->publish.payload;
                    std::string preview(pl.begin(),
                                        pl.begin() + std::min<size_t>(pl.size(),
                                                                      220));
                    fire_on_message(pk->publish.topic,
                                    std::move(pk->publish.payload));
                    break;
                }
                case mqtt::PacketType::Suback:
                case mqtt::PacketType::Pingresp:
                case mqtt::PacketType::Puback:
                    break;
                default:
                    break;
                }
                rbuf.erase(rbuf.begin(),
                           rbuf.begin() + pk->bytes_consumed);
            }
        }
read_loop_exit:
        if (sess->stopped.load()) break;

        // Connection died unexpectedly. Tear down ssl/fd under write_mu
        // (send_message could be holding it; the swap inside reopen_tls
        // also takes write_mu so a concurrent send_message either sees
        // the old ssl about to be freed, or the new ssl). Then loop to
        // reconnect.
        // Deliberately NOT firing on_connect(Lost) here. The slicer's
        // GUI_App.cpp:2183 handler reacts to Lost by clearing the active
        // selection (set_selected_machine("")), which would then call
        // disconnect_printer on us right while we're trying to reconnect
        // — tearing down the very session we're attempting to heal.
        // Instead, we recover transparently. If we never come back, the
        // slicer's is_connected() timeout (DISCONNECT_TIMEOUT = 30s on
        // last_update_time) surfaces the outage naturally.
        if (!connack_seen) {
            backoff_s = std::min(backoff_s * 2, 30);
        }
        {
            std::lock_guard<std::mutex> wlk(sess->write_mu);
            if (sess->ssl) {
                SSL_shutdown(sess->ssl);
                SSL_free(sess->ssl);
                sess->ssl = nullptr;
            }
            if (sess->fd >= 0) {
                close_fd(sess->fd);
                sess->fd = -1;
            }
        }
    }
}

} // namespace Slic3r
