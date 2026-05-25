// bambu_virtual_client — VirtualMqttClient TLS/MQTT loopback test (phase 1b).
//
// Spins a minimal TLS MQTT broker on 127.0.0.1:<random>, generates a
// throw-away RSA self-signed cert in memory, and drives a real
// VirtualMqttClient instance through its full lifecycle:
//
//   1. TLS handshake completes against the in-test broker.
//   2. CONNECT -> CONNACK(rc=0) accepted, on_local_connect fires with
//      status=0.
//   3. client.send_message -> broker decodes the PUBLISH on
//      device/<dev_id>/request, payload matches.
//   4. SUBSCRIBE (auto-issued by the client on CONNACK) is observed by
//      the broker; broker emits a PUBLISH on the subscribed topic; the
//      on_message callback fires with the bytes.
//   5. disconnect_printer + connect_printer on the same dev_id succeeds
//      (idempotent reconnect; we observe a second CONNECT on the broker
//      side).
//   6. 100 rapid PUBLISHes from the client arrive at the broker in order
//      (broker decodes them off the same TLS stream).
//   7. Clean shutdown: disconnect_printer returns, a second
//      disconnect_printer is a no-op, no client thread leak.
//
// Skip behaviour: any bind/handshake failure on loopback returns 77
// (ctest skip), matching BambuStudio-bridge tests/bridge/
// MqttBrokerLoopbackTest.cpp's convention.
//
// Style mirrors tests/MqttFramingTest.cpp — no framework, single
// int main(), fail counter, exit code == g_fails.
//
// Linux-only (the rest of this lib's tests assume POSIX sockets too).

#include "MqttFraming.hpp"
#include "VirtualMqttClient.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <signal.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

using namespace Slic3r;
using namespace Slic3r::virtual_mqtt;

namespace {

constexpr int kCtestSkip = 77;

int g_fails = 0;

void check(bool ok, const char* what) {
    if (!ok) {
        ++g_fails;
        std::fprintf(stderr, "FAIL %s\n", what);
    } else {
        std::fprintf(stderr, "ok   %s\n", what);
    }
}

// --- Self-signed cert (RSA-2048, SHA-256). Mirrors BambuStudio-bridge's
//     CertFactory idiom but in-memory only — no on-disk cache. -----------

struct CertMaterial {
    SSL_CTX* server_ctx = nullptr;
    ~CertMaterial() {
        if (server_ctx) SSL_CTX_free(server_ctx);
    }
};

// Generate an RSA-2048 keypair + self-signed cert and load both into a
// freshly-minted SSL_CTX in TLS_server_method mode. Returns nullptr on
// any OpenSSL failure (the test will SKIP).
SSL_CTX* make_server_ctx() {
    EVP_PKEY*     pkey = nullptr;
    EVP_PKEY_CTX* kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    if (!kctx) return nullptr;
    if (EVP_PKEY_keygen_init(kctx) <= 0 ||
        EVP_PKEY_CTX_set_rsa_keygen_bits(kctx, 2048) <= 0 ||
        EVP_PKEY_keygen(kctx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(kctx);
        return nullptr;
    }
    EVP_PKEY_CTX_free(kctx);

    X509* cert = X509_new();
    if (!cert) { EVP_PKEY_free(pkey); return nullptr; }
    X509_set_version(cert, 2);

    // Random 64-bit serial.
    {
        BIGNUM*        bn = BN_new();
        ASN1_INTEGER*  ai = nullptr;
        if (!bn) { X509_free(cert); EVP_PKEY_free(pkey); return nullptr; }
        BN_rand(bn, 64, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY);
        ai = BN_to_ASN1_INTEGER(bn, nullptr);
        BN_free(bn);
        if (!ai) { X509_free(cert); EVP_PKEY_free(pkey); return nullptr; }
        X509_set_serialNumber(cert, ai);
        ASN1_INTEGER_free(ai);
    }

    X509_gmtime_adj(X509_getm_notBefore(cert), 0);
    X509_gmtime_adj(X509_getm_notAfter(cert), 86400L);
    X509_set_pubkey(cert, pkey);

    X509_NAME* subj = X509_get_subject_name(cert);
    X509_NAME_add_entry_by_txt(
        subj, "CN", MBSTRING_UTF8,
        reinterpret_cast<const unsigned char*>("virtual-mqtt-test"),
        -1, -1, 0);
    X509_set_issuer_name(cert, subj);

    if (X509_sign(cert, pkey, EVP_sha256()) == 0) {
        X509_free(cert); EVP_PKEY_free(pkey); return nullptr;
    }

    SSL_CTX* ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) { X509_free(cert); EVP_PKEY_free(pkey); return nullptr; }
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);

    if (SSL_CTX_use_certificate(ctx, cert) != 1 ||
        SSL_CTX_use_PrivateKey(ctx, pkey) != 1 ||
        SSL_CTX_check_private_key(ctx) != 1) {
        SSL_CTX_free(ctx);
        X509_free(cert); EVP_PKEY_free(pkey);
        return nullptr;
    }

    X509_free(cert);
    EVP_PKEY_free(pkey);
    return ctx;
}

// --- Encoders the broker needs (server-side only). The client-side
//     codec only exports decode_packet + encode_publish; we hand-encode
//     CONNACK / SUBACK / PUBACK here. ---------------------------------

std::vector<uint8_t> encode_connack(uint8_t rc, bool session_present = false) {
    return {0x20, 0x02,
            static_cast<uint8_t>(session_present ? 0x01 : 0x00),
            rc};
}

std::vector<uint8_t> encode_suback(uint16_t packet_id, uint8_t rc) {
    return {0x90, 0x03,
            static_cast<uint8_t>((packet_id >> 8) & 0xFF),
            static_cast<uint8_t>(packet_id & 0xFF),
            rc};
}

std::vector<uint8_t> encode_puback(uint16_t packet_id) {
    return {0x40, 0x02,
            static_cast<uint8_t>((packet_id >> 8) & 0xFF),
            static_cast<uint8_t>(packet_id & 0xFF)};
}

// --- Broker --------------------------------------------------------------
//
// Single connection at a time (the client only opens one session per
// dev_id and the test only uses one dev_id). Listens on 127.0.0.1:0, the
// kernel picks a free ephemeral port, the test discovers it via
// getsockname().
//
// Threading: one accept thread that loops accept() and, on each new
// connection, runs the per-connection MQTT loop inline (sequential — one
// connection at a time is enough for this test). All recorded state is
// guarded by a mutex; the main test thread reads it with snapshot
// methods.

struct ReceivedPublish {
    std::string          topic;
    std::vector<uint8_t> payload;
    uint8_t              qos = 0;
    uint16_t             packet_id = 0;
};

class TestBroker {
public:
    TestBroker() {
        m_ctx = make_server_ctx();
    }
    ~TestBroker() {
        stop();
        if (m_ctx) SSL_CTX_free(m_ctx);
    }
    bool ctx_ok() const { return m_ctx != nullptr; }

    // Bind to 127.0.0.1:0. Returns false on bind/listen failure.
    bool start() {
        m_listen_fd = ::socket(AF_INET, SOCK_STREAM, 0);
        if (m_listen_fd < 0) return false;
        int one = 1;
        ::setsockopt(m_listen_fd, SOL_SOCKET, SO_REUSEADDR,
                     &one, sizeof(one));
        sockaddr_in addr{};
        addr.sin_family      = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port        = 0;
        if (::bind(m_listen_fd,
                   reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
            ::close(m_listen_fd); m_listen_fd = -1;
            return false;
        }
        if (::listen(m_listen_fd, 4) < 0) {
            ::close(m_listen_fd); m_listen_fd = -1;
            return false;
        }
        sockaddr_in bound{};
        socklen_t   bound_len = sizeof(bound);
        if (::getsockname(m_listen_fd,
                          reinterpret_cast<sockaddr*>(&bound),
                          &bound_len) < 0) {
            ::close(m_listen_fd); m_listen_fd = -1;
            return false;
        }
        m_bound_port = ntohs(bound.sin_port);

        m_stop.store(false);
        m_thread = std::thread([this] { accept_loop(); });
        return true;
    }

    void stop() {
        m_stop.store(true);
        if (m_listen_fd >= 0) {
            // Wake accept() if it's blocked.
            ::shutdown(m_listen_fd, SHUT_RDWR);
            ::close(m_listen_fd);
            m_listen_fd = -1;
        }
        if (m_thread.joinable()) m_thread.join();
    }

    uint16_t bound_port() const { return m_bound_port; }

    // Snapshot accessors used by the test main.
    std::vector<ReceivedPublish> publishes_copy() {
        std::lock_guard<std::mutex> lk(m_mu);
        return m_publishes;
    }
    std::vector<std::string> subscribes_copy() {
        std::lock_guard<std::mutex> lk(m_mu);
        return m_subscribes;
    }
    int connect_count() {
        std::lock_guard<std::mutex> lk(m_mu);
        return m_connects;
    }

    // Wait until at least n PUBLISHes have arrived (or timeout).
    bool wait_for_publishes(size_t want, std::chrono::milliseconds budget) {
        auto deadline = std::chrono::steady_clock::now() + budget;
        std::unique_lock<std::mutex> lk(m_mu);
        return m_cv.wait_until(lk, deadline,
            [&] { return m_publishes.size() >= want; });
    }
    bool wait_for_subscribes(size_t want, std::chrono::milliseconds budget) {
        auto deadline = std::chrono::steady_clock::now() + budget;
        std::unique_lock<std::mutex> lk(m_mu);
        return m_cv.wait_until(lk, deadline,
            [&] { return m_subscribes.size() >= want; });
    }
    bool wait_for_connects(int want, std::chrono::milliseconds budget) {
        auto deadline = std::chrono::steady_clock::now() + budget;
        std::unique_lock<std::mutex> lk(m_mu);
        return m_cv.wait_until(lk, deadline,
            [&] { return m_connects >= want; });
    }

    // Push a downstream PUBLISH to the currently-active client (if any).
    // Returns false if no client is connected.
    bool inject_downstream(const std::string& topic,
                           const std::vector<uint8_t>& payload,
                           uint8_t qos) {
        std::lock_guard<std::mutex> lk(m_mu);
        if (!m_active_ssl) return false;
        auto pkt = encode_publish(topic, payload, qos,
                                  /*retain=*/false,
                                  /*packet_id=*/qos ? 1 : 0,
                                  /*dup=*/false);
        return SSL_write(m_active_ssl, pkt.data(),
                         static_cast<int>(pkt.size()))
               == static_cast<int>(pkt.size());
    }

private:
    void accept_loop() {
        while (!m_stop.load()) {
            sockaddr_in peer{};
            socklen_t   peer_len = sizeof(peer);
            int conn = ::accept(m_listen_fd,
                                reinterpret_cast<sockaddr*>(&peer),
                                &peer_len);
            if (conn < 0) {
                if (m_stop.load()) return;
                continue;
            }
            handle_connection(conn);
        }
    }

    // Read all bytes available, append to buf. Returns false on EOF/error.
    bool ssl_read_some(SSL* ssl, std::vector<uint8_t>& buf,
                      std::chrono::milliseconds timeout) {
        int fd = SSL_get_fd(ssl);
        fd_set rfds; FD_ZERO(&rfds); FD_SET(fd, &rfds);
        timeval tv{};
        tv.tv_sec  = static_cast<long>(timeout.count() / 1000);
        tv.tv_usec = static_cast<long>((timeout.count() % 1000) * 1000);
        if (::select(fd + 1, &rfds, nullptr, nullptr, &tv) <= 0) {
            return true; // timeout — no data, but not fatal
        }
        uint8_t chunk[4096];
        int n = SSL_read(ssl, chunk, sizeof(chunk));
        if (n <= 0) {
            int e = SSL_get_error(ssl, n);
            if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE)
                return true;
            return false;
        }
        buf.insert(buf.end(), chunk, chunk + n);
        return true;
    }

    void handle_connection(int conn) {
        SSL* ssl = SSL_new(m_ctx);
        if (!ssl) { ::close(conn); return; }
        SSL_set_fd(ssl, conn);
        if (SSL_accept(ssl) != 1) {
            SSL_free(ssl); ::close(conn); return;
        }
        {
            std::lock_guard<std::mutex> lk(m_mu);
            m_active_ssl = ssl;
        }

        std::vector<uint8_t> rbuf;
        bool alive = true;
        auto t_deadline = std::chrono::steady_clock::now() +
                          std::chrono::seconds(60);

        while (alive && !m_stop.load() &&
               std::chrono::steady_clock::now() < t_deadline) {
            // Try to decode anything already buffered before reading.
            bool progressed = true;
            while (progressed) {
                progressed = false;
                if (rbuf.empty()) break;

                // The client's decode_packet handles CONNACK/PUBLISH/
                // PUBACK/SUBACK/PINGRESP — i.e. server-to-client frames.
                // For client-to-server we need to peek at the fixed
                // header type ourselves: handle CONNECT (0x10),
                // SUBSCRIBE (0x82), DISCONNECT (0xE0), PINGREQ (0xC0),
                // and PUBLISH via the shared decoder (PUBLISH is
                // direction-symmetric).
                const uint8_t hdr0 = rbuf[0];
                const uint8_t type = hdr0 & 0xF0;

                if (type == 0x30) {
                    // PUBLISH — direction-agnostic. Reuse decode_packet.
                    auto pk = decode_packet(rbuf.data(), rbuf.size());
                    if (!pk) break; // truncated
                    if (pk->error != DecodeError::Ok) { alive = false; break; }
                    {
                        std::lock_guard<std::mutex> lk(m_mu);
                        ReceivedPublish r;
                        r.topic     = pk->publish.topic;
                        r.payload   = pk->publish.payload;
                        r.qos       = pk->publish.qos;
                        r.packet_id = pk->publish.packet_id;
                        m_publishes.push_back(std::move(r));
                        m_cv.notify_all();
                    }
                    if (pk->publish.qos == 1) {
                        auto ack = encode_puback(pk->publish.packet_id);
                        SSL_write(ssl, ack.data(),
                                  static_cast<int>(ack.size()));
                    }
                    rbuf.erase(rbuf.begin(),
                               rbuf.begin() + pk->bytes_consumed);
                    progressed = true;
                    continue;
                }

                // Other client-to-server frames: parse remaining length
                // ourselves. Both we and the client cap at 4-byte varint
                // (MQTT 3.1.1 §2.2.3).
                size_t rl = 0, mult = 1, i = 1;
                bool   varint_ok = false;
                for (; i < rbuf.size() && i <= 4; ++i) {
                    rl += (rbuf[i] & 0x7F) * mult;
                    if (!(rbuf[i] & 0x80)) { varint_ok = true; break; }
                    mult *= 128;
                }
                if (!varint_ok) break; // truncated varint
                const size_t header_len = i + 1;
                if (rbuf.size() < header_len + rl) break; // truncated body

                if (type == 0x10) {
                    // CONNECT — we don't bother parsing the payload
                    // (the test only cares that the frame arrived).
                    // Reply CONNACK rc=0.
                    {
                        std::lock_guard<std::mutex> lk(m_mu);
                        ++m_connects;
                        m_cv.notify_all();
                    }
                    auto ack = encode_connack(0);
                    if (SSL_write(ssl, ack.data(),
                                  static_cast<int>(ack.size()))
                        != static_cast<int>(ack.size())) {
                        alive = false;
                    }
                } else if ((hdr0 & 0xF0) == 0x80) {
                    // SUBSCRIBE. Fixed header 0x82, body is:
                    //   pid (2B) | (topic length-prefixed | qos)+
                    if (rl < 3) { alive = false; break; }
                    const uint8_t* p = rbuf.data() + header_len;
                    uint16_t pid = (uint16_t(p[0]) << 8) | uint16_t(p[1]);
                    p += 2;
                    uint16_t tlen = (uint16_t(p[0]) << 8) | uint16_t(p[1]);
                    p += 2;
                    std::string topic(reinterpret_cast<const char*>(p), tlen);
                    p += tlen;
                    uint8_t want_qos = *p;
                    {
                        std::lock_guard<std::mutex> lk(m_mu);
                        m_subscribes.push_back(topic);
                        m_cv.notify_all();
                    }
                    auto ack = encode_suback(pid, want_qos);
                    if (SSL_write(ssl, ack.data(),
                                  static_cast<int>(ack.size()))
                        != static_cast<int>(ack.size())) {
                        alive = false;
                    }
                } else if (type == 0xC0) {
                    // PINGREQ -> PINGRESP. (Client doesn't emit one
                    // currently, but be future-proof.)
                    const uint8_t resp[2] = {0xD0, 0x00};
                    SSL_write(ssl, resp, sizeof(resp));
                } else if (type == 0xE0) {
                    // DISCONNECT — client is going away. Exit cleanly.
                    alive = false;
                } else {
                    // Unknown frame type — drop the connection so the
                    // test fails loudly rather than spinning.
                    alive = false;
                }
                rbuf.erase(rbuf.begin(), rbuf.begin() + header_len + rl);
                progressed = true;
            }
            if (!alive) break;
            if (!ssl_read_some(ssl, rbuf, std::chrono::milliseconds(100))) {
                alive = false;
            }
        }

        {
            std::lock_guard<std::mutex> lk(m_mu);
            m_active_ssl = nullptr;
        }
        SSL_shutdown(ssl);
        SSL_free(ssl);
        ::close(conn);
    }

    SSL_CTX*           m_ctx        = nullptr;
    int                m_listen_fd  = -1;
    uint16_t           m_bound_port = 0;
    std::atomic<bool>  m_stop{false};
    std::thread        m_thread;

    std::mutex                   m_mu;
    std::condition_variable      m_cv;
    SSL*                         m_active_ssl = nullptr;
    int                          m_connects   = 0;
    std::vector<std::string>     m_subscribes;
    std::vector<ReceivedPublish> m_publishes;
};

void init_openssl_once() {
    static struct Init {
        Init() {
            SSL_load_error_strings();
            OpenSSL_add_ssl_algorithms();
        }
    } s_init;
    (void)s_init;
}

} // namespace

int main() {
    // OpenSSL SSL_write on a peer-closed socket raises SIGPIPE on Linux
    // before any return code is observed. Both the in-test broker (when
    // the client side has already closed) and the client's DISCONNECT
    // emit during teardown can hit this. Ignore so the test doesn't get
    // killed mid-shutdown.
    ::signal(SIGPIPE, SIG_IGN);

    init_openssl_once();

    TestBroker broker;
    if (!broker.ctx_ok()) {
        std::fprintf(stderr, "SKIP: OpenSSL self-signed cert generation failed\n");
        return kCtestSkip;
    }
    if (!broker.start()) {
        std::fprintf(stderr,
                     "SKIP: couldn't bind broker on 127.0.0.1 (sandbox?)\n");
        return kCtestSkip;
    }
    const uint16_t port = broker.bound_port();
    std::fprintf(stderr, "broker listening on 127.0.0.1:%u\n",
                 static_cast<unsigned>(port));

    const std::string dev_id      = "FFFF1234567890";
    const std::string access_code = "TESTACCESS";

    // Fresh VirtualMqttClient instance (do NOT use the process-wide
    // singleton — tests should be hermetic).
    VirtualMqttClient client;
    client.set_port_resolver(
        [port](const std::string&) -> uint16_t { return port; });

    // ---- Wire up callbacks --------------------------------------------
    std::atomic<int>         on_connect_status{-999};
    std::atomic<int>         on_connect_count{0};
    std::mutex               msg_mu;
    std::condition_variable  msg_cv;
    std::vector<std::string> received_msgs;

    client.set_on_local_connect(
        [&](int status, std::string /*dev*/, std::string /*msg*/) {
            on_connect_status.store(status);
            on_connect_count.fetch_add(1);
        });
    client.set_on_message(
        [&](std::string /*dev*/, std::string msg) {
            std::lock_guard<std::mutex> lk(msg_mu);
            received_msgs.push_back(std::move(msg));
            msg_cv.notify_all();
        });

    // ---- (1) TLS handshake + (2) CONNECT/CONNACK ----------------------
    int rc = client.connect_printer(dev_id, "127.0.0.1", access_code);
    check(rc == 0, "connect_printer returns 0");

    check(broker.wait_for_connects(1, std::chrono::seconds(5)),
          "broker observed CONNECT (TLS+MQTT handshake)");

    // Wait for the on_local_connect callback to fire with status=0.
    {
        auto deadline = std::chrono::steady_clock::now() +
                        std::chrono::seconds(3);
        while (on_connect_status.load() != 0 &&
               std::chrono::steady_clock::now() < deadline) {
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
        }
        check(on_connect_status.load() == 0,
              "on_local_connect fired with status=0");
    }

    // Client auto-subscribes to device/<dev_id>/report on CONNACK.
    check(broker.wait_for_subscribes(1, std::chrono::seconds(3)),
          "broker observed SUBSCRIBE");
    {
        auto subs = broker.subscribes_copy();
        const std::string want = "device/" + dev_id + "/report";
        check(!subs.empty() && subs[0] == want,
              "auto-subscribed topic matches device/<dev_id>/report");
    }

    // ---- (3) client.send_message -> broker decodes -------------------
    const std::string body = "{\"info\":{\"command\":\"get_version\"}}";
    rc = client.send_message(dev_id, body, /*qos=*/0);
    check(rc == 0, "send_message returns 0");

    check(broker.wait_for_publishes(1, std::chrono::seconds(3)),
          "broker received the PUBLISH");
    {
        auto pubs = broker.publishes_copy();
        check(!pubs.empty(), "broker has >=1 publish");
        if (!pubs.empty()) {
            check(pubs[0].topic == "device/" + dev_id + "/request",
                  "publish topic matches device/<dev_id>/request");
            std::string got(pubs[0].payload.begin(), pubs[0].payload.end());
            check(got == body, "publish payload matches");
        }
    }

    // ---- (4) broker -> client downstream PUBLISH -> on_message ------
    const std::string ds_topic = "device/" + dev_id + "/report";
    const std::string ds_body  = "{\"print\":{\"command\":\"push_status\"}}";
    {
        std::vector<uint8_t> p(ds_body.begin(), ds_body.end());
        check(broker.inject_downstream(ds_topic, p, /*qos=*/0),
              "broker downstream inject ok");
    }
    {
        std::unique_lock<std::mutex> lk(msg_mu);
        bool got = msg_cv.wait_for(lk, std::chrono::seconds(3),
                                   [&] { return !received_msgs.empty(); });
        check(got, "on_message callback fired");
        if (got) {
            check(received_msgs.front() == ds_body,
                  "on_message payload matches downstream body");
        }
    }

    // ---- (5) Idempotent reconnect ------------------------------------
    on_connect_status.store(-999);
    on_connect_count.store(0);
    rc = client.disconnect_printer(dev_id);
    check(rc == 0, "first disconnect_printer returns 0");

    rc = client.connect_printer(dev_id, "127.0.0.1", access_code);
    check(rc == 0, "re-connect_printer on same dev_id returns 0");

    check(broker.wait_for_connects(2, std::chrono::seconds(5)),
          "broker observed second CONNECT after reconnect");
    {
        auto deadline = std::chrono::steady_clock::now() +
                        std::chrono::seconds(3);
        while (on_connect_status.load() != 0 &&
               std::chrono::steady_clock::now() < deadline) {
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
        }
        check(on_connect_status.load() == 0,
              "on_local_connect re-fired with status=0 after reconnect");
    }

    // ---- (6) 100-message ordering ------------------------------------
    //
    // Snapshot how many publishes the broker has already seen (from
    // test 3) so we can index into the suffix. The broker subscribe
    // also re-issued from the client on the new CONNACK; ignore it.
    const size_t baseline = broker.publishes_copy().size();
    const int    N        = 100;
    for (int i = 0; i < N; ++i) {
        char buf[64];
        std::snprintf(buf, sizeof(buf),
                      "{\"i\":%d,\"v\":\"payload-%d\"}", i, i);
        int wr = client.send_message(dev_id, buf, /*qos=*/0);
        if (wr != 0) {
            ++g_fails;
            std::fprintf(stderr, "FAIL send_message #%d -> %d\n", i, wr);
            break;
        }
    }
    check(broker.wait_for_publishes(baseline + N, std::chrono::seconds(15)),
          "broker received all 100 ordered publishes");
    {
        auto pubs = broker.publishes_copy();
        bool order_ok = pubs.size() >= baseline + N;
        for (int i = 0; order_ok && i < N; ++i) {
            char want[64];
            std::snprintf(want, sizeof(want),
                          "{\"i\":%d,\"v\":\"payload-%d\"}", i, i);
            std::string got(pubs[baseline + i].payload.begin(),
                            pubs[baseline + i].payload.end());
            if (got != want) {
                order_ok = false;
                std::fprintf(stderr,
                             "FAIL ordering at i=%d: got=%s want=%s\n",
                             i, got.c_str(), want);
            }
        }
        check(order_ok, "100 publishes arrived in send order");
    }

    // ---- (7) Clean shutdown -----------------------------------------
    //
    // disconnect_printer joins the I/O thread synchronously. Give it a
    // generous-but-finite budget and observe by timing.
    auto t0 = std::chrono::steady_clock::now();
    rc = client.disconnect_printer(dev_id);
    auto elapsed = std::chrono::steady_clock::now() - t0;
    check(rc == 0, "final disconnect_printer returns 0");
    check(elapsed < std::chrono::seconds(5),
          "disconnect_printer completed within 5s");

    rc = client.disconnect_printer(dev_id);
    check(rc == 0, "second disconnect_printer is a no-op (returns 0)");

    broker.stop();

    if (g_fails) {
        std::fprintf(stderr,
                     "VirtualMqttClientLoopbackTest: %d assertion(s) failed\n",
                     g_fails);
        return 1;
    }
    std::printf("VirtualMqttClientLoopbackTest: ok\n");
    return 0;
}
