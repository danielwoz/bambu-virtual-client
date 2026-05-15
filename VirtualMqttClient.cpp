// VirtualMqttClient implementation. See header for design rationale.

#include "VirtualMqttClient.hpp"

#include "MqttFraming.hpp"

#include <array>
#include <atomic>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <openssl/err.h>
#include <openssl/ssl.h>

namespace Slic3r {

namespace {

namespace mqtt = ::Slic3r::virtual_mqtt;

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

// Open a TCP socket to host:port. Returns fd or -1.
int tcp_connect(const std::string& host, uint16_t port) {
    addrinfo hints{};
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    addrinfo* res = nullptr;
    const std::string port_str = std::to_string(port);
    if (::getaddrinfo(host.c_str(), port_str.c_str(), &hints, &res) != 0)
        return -1;
    int fd = -1;
    for (auto* a = res; a; a = a->ai_next) {
        fd = ::socket(a->ai_family, a->ai_socktype, a->ai_protocol);
        if (fd < 0) continue;
        if (::connect(fd, a->ai_addr, a->ai_addrlen) == 0) break;
        ::close(fd);
        fd = -1;
    }
    ::freeaddrinfo(res);
    return fd;
}

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
    if (port == 0) port = 8883;

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
            ::close(fd);
            fd = -1;
        } else {
            SSL_set_fd(ssl, fd);
            int rc = SSL_connect(ssl);
            if (rc != 1) {
                const int  ssl_err = SSL_get_error(ssl, rc);
                const auto err_q   = ERR_get_error();
                SSL_free(ssl);
                ssl = nullptr;
                ::close(fd);
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
        ::shutdown(doomed->fd, SHUT_RDWR);
    if (doomed->io_thread.joinable())
        doomed->io_thread.join();
    if (doomed->ssl) {
        SSL_shutdown(doomed->ssl);
        SSL_free(doomed->ssl);
        doomed->ssl = nullptr;
    }
    if (doomed->fd >= 0) {
        ::close(doomed->fd);
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
        return -1;
    }
    int n = SSL_write(sess->ssl, pkt.data(), static_cast<int>(pkt.size()));
    if (n != static_cast<int>(pkt.size())) {
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
        if (!new_ssl) { ::close(new_fd); return false; }
        SSL_set_fd(new_ssl, new_fd);
        if (SSL_connect(new_ssl) != 1) {
            SSL_free(new_ssl);
            ::close(new_fd);
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
                ::usleep(100 * 1000); // 100 ms slices for prompt stop
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
                ::close(sess->fd);
                sess->fd = -1;
            }
        }
    }
}

} // namespace Slic3r
