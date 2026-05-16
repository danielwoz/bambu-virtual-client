// VirtualBambuTunnel implementation. See header for design.
//
// Networking: boost::asio for TCP + DNS resolve. TLS: raw OpenSSL
// (TLS 1.2, verify=false) on top of the asio socket's native_handle().
// We release() the asio socket so the SSL object owns the fd lifetime;
// SSL_read/SSL_write and the non-blocking select() probe on the
// underlying fd continue to work unchanged on POSIX, and route to
// Winsock equivalents on Windows.

#include "VirtualBambuTunnel.hpp"

#include <boost/asio.hpp>
#include <boost/system/error_code.hpp>

#ifdef _WIN32
#  include <winsock2.h>
#  include <ws2tcpip.h>
#else
#  include <sys/select.h>
#  include <sys/socket.h>
#  include <unistd.h>
#endif

#include <openssl/err.h>
#include <openssl/ssl.h>

#include <cerrno>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace Slic3r {
namespace virtual_tunnel {

namespace {

namespace asio = boost::asio;
using asio::ip::tcp;
using boost::system::error_code;

// A pending sample held until the next ReadSample. We own the buffer for
// the caller (PrinterFileSystem::HandleResponse keeps the pointer until
// it's done parsing).
struct QueuedSample {
    std::vector<uint8_t> buffer;
};

constexpr int CTRL_TYPE_TRACK = 0x3001;

} // namespace

// Layout: header magic, then the rest of the state. The dispatcher uses
// `memcpy` on the first 4 bytes to verify the magic before casting up.
struct VirtualTunnel {
    uint32_t magic = kMagic;

    std::string host;
    uint16_t    port = 0;
    std::string dev_id;
    std::string access_code;

    SSL_CTX* ssl_ctx = nullptr;
    SSL*     ssl     = nullptr;
    int      fd      = -1;

    // Read state: one frame at a time. We pre-allocate a sample buffer
    // and copy each incoming frame into it; the pointer we hand back via
    // Bambu_Sample is owned by `sample_buf` and stays valid until the
    // *next* ReadSample call.
    std::vector<uint8_t> sample_buf;

    // Incremental read state for the non-blocking ReadSample path. The
    // slicer's worker thread polls ReadSample repeatedly; we accumulate
    // 4 bytes of frame length, then the payload, then return the
    // assembled frame on the call that completes the payload. All
    // intermediate calls return Bambu_would_block so the caller never
    // blocks waiting for the server (which only sends after we send a
    // request — a chicken-and-egg if we blocked here).
    uint8_t              read_lenbuf[4]   = {0, 0, 0, 0};
    int                  read_lenbuf_got  = 0; // 0..4
    std::vector<uint8_t> read_payload;
    uint32_t             read_payload_n   = 0; // total expected
    uint32_t             read_payload_got = 0;

    // Multiple frames might be sitting in our SSL buffer; we drain them
    // into this queue so successive ReadSample calls each return one.
    std::deque<QueuedSample> queue;

    // Stop flag for Close()/Destroy().
    bool closed = false;

    // Optional logger from the slicer; we route a few key events through
    // it so the PrinterFileSystem's log macros show our tunnel in the
    // user's debug log alongside real-tunnel events.
    Logger logger     = nullptr;
    void*  logger_ctx = nullptr;
};

namespace {

void vlog(VirtualTunnel* t, int level, const char* msg) {
    if (t && t->logger) t->logger(t->logger_ctx, level, msg);
}

// Parse host/port/dev_id/access_code out of a URL of the form
//   bambu:///virtual/<host>:<port>?dev_id=...&access_code=...
bool parse_virtual_url(const char* url, VirtualTunnel* t) {
    constexpr const char* kPrefix = "bambu:///virtual/";
    const std::string s = url ? std::string(url) : std::string();
    if (s.rfind(kPrefix, 0) != 0) return false;
    std::string rest = s.substr(std::strlen(kPrefix));

    // Split host:port?query
    auto qpos = rest.find('?');
    std::string hostport = (qpos == std::string::npos) ? rest : rest.substr(0, qpos);
    std::string query    = (qpos == std::string::npos) ? std::string() : rest.substr(qpos + 1);

    auto colon = hostport.find(':');
    if (colon == std::string::npos) return false;
    t->host = hostport.substr(0, colon);
    t->port = static_cast<uint16_t>(std::atoi(hostport.substr(colon + 1).c_str()));
    if (t->host.empty() || t->port == 0) return false;

    // Parse k=v&k=v
    size_t pos = 0;
    while (pos < query.size()) {
        size_t amp = query.find('&', pos);
        std::string kv = query.substr(pos, amp == std::string::npos ? std::string::npos : amp - pos);
        auto eq = kv.find('=');
        if (eq != std::string::npos) {
            const std::string k = kv.substr(0, eq);
            const std::string v = kv.substr(eq + 1);
            if      (k == "dev_id")      t->dev_id      = v;
            else if (k == "access_code") t->access_code = v;
        }
        if (amp == std::string::npos) break;
        pos = amp + 1;
    }
    return true;
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

inline void shutdown_fd(int fd) {
    if (fd < 0) return;
#ifdef _WIN32
    ::shutdown(fd, SD_BOTH);
#else
    ::shutdown(fd, SHUT_RDWR);
#endif
}

inline void sleep_ms(int ms) {
    std::this_thread::sleep_for(std::chrono::milliseconds(ms));
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

// Try to read ONE complete frame from `ssl` into `out`. Returns:
//   1 = a frame was decoded (placed in `out`)
//   0 = would block (no data ready, or partial)
//  -1 = error / closed
//
// We do not loop until "all frames drained"; PrinterFileSystem polls
// ReadSample and is happy with one-at-a-time. Implementation: blocking
// read of 4-byte length, then `length` bytes of payload. The slicer
// dispatcher calls us from a thread that's already happy to block.
int recv_frame_blocking(SSL* ssl, std::vector<uint8_t>& out) {
    uint8_t lenbuf[4];
    int     got = 0;
    while (got < 4) {
        int r = SSL_read(ssl, lenbuf + got, 4 - got);
        if (r <= 0) {
            const int err = SSL_get_error(ssl, r);
            if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
                continue;
            return -1;
        }
        got += r;
    }
    const uint32_t n =
        (static_cast<uint32_t>(lenbuf[0]) << 24) |
        (static_cast<uint32_t>(lenbuf[1]) << 16) |
        (static_cast<uint32_t>(lenbuf[2]) <<  8) |
         static_cast<uint32_t>(lenbuf[3]);
    if (n == 0 || n > 4u * 1024u * 1024u) return -1;

    out.assign(n, 0);
    size_t off = 0;
    while (off < n) {
        int r = SSL_read(ssl, out.data() + off, static_cast<int>(n - off));
        if (r <= 0) {
            const int err = SSL_get_error(ssl, r);
            if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
                continue;
            return -1;
        }
        off += static_cast<size_t>(r);
    }
    return 1;
}

bool send_frame(SSL* ssl, const uint8_t* data, size_t n) {
    const uint8_t lenbuf[4] = {
        static_cast<uint8_t>((n >> 24) & 0xff),
        static_cast<uint8_t>((n >> 16) & 0xff),
        static_cast<uint8_t>((n >>  8) & 0xff),
        static_cast<uint8_t>( n        & 0xff),
    };
    size_t off = 0;
    while (off < 4) {
        int r = SSL_write(ssl, lenbuf + off, static_cast<int>(4 - off));
        if (r <= 0) {
            const int err = SSL_get_error(ssl, r);
            if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
                continue;
            return false;
        }
        off += r;
    }
    off = 0;
    while (off < n) {
        int r = SSL_write(ssl, data + off, static_cast<int>(n - off));
        if (r <= 0) {
            const int err = SSL_get_error(ssl, r);
            if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
                continue;
            return false;
        }
        off += r;
    }
    return true;
}

// Lazy global SSL_CTX. PrinterFileSystem only ever has at most a handful
// of tunnels open at once; sharing one client SSL_CTX is fine.
SSL_CTX* client_ctx() {
    static std::once_flag init_once;
    std::call_once(init_once, []() {
        SSL_load_error_strings();
        OpenSSL_add_ssl_algorithms();
    });
    static SSL_CTX* g = []() {
        SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
        if (!ctx) return (SSL_CTX*)nullptr;
        // The bridge's VirtualTunnelServer uses the same self-signed cert
        // as the rest of the bridge (per-device CertFactory). We accept
        // it — verify=false matches the rest of our virtual flow.
        SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nullptr);
        SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
        return ctx;
    }();
    return g;
}

} // anonymous namespace

bool url_is_virtual(char const* url) {
    if (!url) return false;
    return std::strncmp(url, "bambu:///virtual/",
                        std::strlen("bambu:///virtual/")) == 0;
}

bool is_virtual_tunnel(Bambu_Tunnel t) {
    if (!t) return false;
    uint32_t head = 0;
    std::memcpy(&head, t, sizeof(head));
    return head == kMagic;
}

int Bambu_Create_virtual(Bambu_Tunnel* out, char const* url) {
    if (!out) return -1;
    auto t = new VirtualTunnel();
    if (!parse_virtual_url(url, t)) {
        delete t;
        return -1;
    }
    *out = static_cast<Bambu_Tunnel>(t);
    return 0;
}

int Bambu_Open_virtual(Bambu_Tunnel tunnel) {
    auto* t = static_cast<VirtualTunnel*>(tunnel);
    if (!t) return -1;
    if (t->ssl) return 0;

    SSL_CTX* ctx = client_ctx();
    if (!ctx) return -1;

    int fd = tcp_connect(t->host, t->port);
    if (fd < 0) {
        return -1;
    }
    SSL* ssl = SSL_new(ctx);
    if (!ssl) { close_fd(fd); return -1; }
    SSL_set_fd(ssl, fd);
    const int conn_rc = SSL_connect(ssl);
    if (conn_rc != 1) {
        SSL_free(ssl);
        close_fd(fd);
        return -1;
    }

    t->fd  = fd;
    t->ssl = ssl;
    vlog(t, 0, "[virtual-tunnel] open ok");
    return 0;
}

int Bambu_StartStream_virtual(Bambu_Tunnel /*tunnel*/, bool /*video*/) {
    // The slicer's Storage tab only ever calls StartStreamEx(CTRL_TYPE).
    // We accept legacy StartStream too; both are no-ops for us — the
    // tunnel only carries the CTRL_TYPE control stream.
    return 0;
}

int Bambu_StartStreamEx_virtual(Bambu_Tunnel /*tunnel*/, int /*type*/) {
    return 0;
}

int Bambu_SendMessage_virtual(Bambu_Tunnel tunnel, int /*ctrl*/,
                              char const* data, int len) {
    auto* t = static_cast<VirtualTunnel*>(tunnel);
    if (!t || !t->ssl) return -1;
    if (!send_frame(t->ssl,
                    reinterpret_cast<const uint8_t*>(data),
                    static_cast<size_t>(len))) {
        return -1;
    }
    return 0;
}

// Try to read up to `want` bytes from `ssl` into `buf` WITHOUT blocking.
// Returns:
//   >0  number of bytes actually read
//    0  no data ready right now (would_block)
//   -1  error / closed
//
// Drives the read via a select() probe on the underlying fd plus a
// SSL_pending() short-circuit. If select says "ready" we still call
// SSL_read which may consume the bytes without making them visible to
// us as application data (TLS records, alerts, etc.) — that's fine,
// the next poll picks up where we left off.
static int ssl_read_nonblocking(SSL* ssl, int fd, uint8_t* buf, int want) {
    if (SSL_pending(ssl) <= 0) {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(fd, &rfds);
        timeval tv{0, 0}; // immediate
        const int sel = ::select(fd + 1, &rfds, nullptr, nullptr, &tv);
        if (sel == 0) return 0;
        if (sel < 0) {
            if (errno == EINTR) return 0;
            return -1;
        }
    }
    const int n = SSL_read(ssl, buf, want);
    if (n > 0) return n;
    const int err = SSL_get_error(ssl, n);
    if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) return 0;
    return -1;
}

int Bambu_ReadSample_virtual(Bambu_Tunnel tunnel, Bambu_Sample* sample) {
    {
        static thread_local int enter_tick = 0;
        if (enter_tick < 10 || (enter_tick % 100) == 0) {
        }
        ++enter_tick;
    }
    auto* t = static_cast<VirtualTunnel*>(tunnel);
    if (!t || !t->ssl || !sample) return Bambu_stream_end;
    if (t->closed) return Bambu_stream_end;

    // The slicer's PrinterFileSystem worker thread drives both send and
    // receive on the same thread (PrinterFileSystem.cpp:1593-1623). If
    // we block on SSL_read inside this call the worker never gets back
    // to m_cond.timed_wait, so a queued LIST_INFO message never reaches
    // Bambu_SendMessage and Storage spins forever. Real libBambuSource
    // returns Bambu_would_block when nothing's ready; we mirror that.
    //
    // The protocol is 4-byte big-endian length, then `n` bytes of
    // payload. We track partial reads of both length and payload across
    // calls so a single call to this function never blocks for any
    // appreciable time — it pulls whatever bytes are ready, sleeps a
    // little if nothing is, and returns either Bambu_would_block (no
    // complete frame yet) or 0 (frame in `*sample`).

    // First, finish reading the 4-byte length prefix.
    while (t->read_lenbuf_got < 4) {
        const int got = ssl_read_nonblocking(
            t->ssl, t->fd,
            t->read_lenbuf + t->read_lenbuf_got,
            4 - t->read_lenbuf_got);
        if (got == 0) {
            // No data right now. Tiny sleep so we don't spin the
            // slicer's worker thread (the outer loop's would_block
            // path will further sleep up to 1000 ms).
            sleep_ms(20);
            return Bambu_would_block;
        }
        if (got < 0) return Bambu_stream_end;
        t->read_lenbuf_got += got;
    }
    if (t->read_payload_n == 0) {
        const uint32_t n =
            (static_cast<uint32_t>(t->read_lenbuf[0]) << 24) |
            (static_cast<uint32_t>(t->read_lenbuf[1]) << 16) |
            (static_cast<uint32_t>(t->read_lenbuf[2]) <<  8) |
             static_cast<uint32_t>(t->read_lenbuf[3]);
        if (n == 0 || n > 4u * 1024u * 1024u) {
            return Bambu_stream_end;
        }
        t->read_payload_n   = n;
        t->read_payload_got = 0;
        t->read_payload.assign(n, 0);
    }

    // Then drain the payload.
    while (t->read_payload_got < t->read_payload_n) {
        const int got = ssl_read_nonblocking(
            t->ssl, t->fd,
            t->read_payload.data() + t->read_payload_got,
            static_cast<int>(t->read_payload_n - t->read_payload_got));
        if (got == 0) {
            sleep_ms(20);
            return Bambu_would_block;
        }
        if (got < 0) return Bambu_stream_end;
        t->read_payload_got += static_cast<uint32_t>(got);
    }

    // One complete frame assembled — hand it to the slicer and reset
    // the per-call state for the next frame.
    t->sample_buf = std::move(t->read_payload);
    t->read_payload   = {};
    t->read_payload_n = 0;
    t->read_payload_got = 0;
    t->read_lenbuf_got = 0;

    sample->itrack      = CTRL_TYPE_TRACK;
    sample->size        = static_cast<int>(t->sample_buf.size());
    sample->flags       = 0;
    sample->buffer      = t->sample_buf.data();
    sample->decode_time = 0;
    return 0;
}

void Bambu_Close_virtual(Bambu_Tunnel tunnel) {
    auto* t = static_cast<VirtualTunnel*>(tunnel);
    if (!t) return;
    t->closed = true;
    if (t->ssl) {
        SSL_shutdown(t->ssl);
        SSL_free(t->ssl);
        t->ssl = nullptr;
    }
    if (t->fd >= 0) {
        shutdown_fd(t->fd);
        close_fd(t->fd);
        t->fd = -1;
    }
}

void Bambu_Destroy_virtual(Bambu_Tunnel tunnel) {
    auto* t = static_cast<VirtualTunnel*>(tunnel);
    if (!t) return;
    if (!t->closed) Bambu_Close_virtual(tunnel);
    delete t;
}

void Bambu_SetLogger_virtual(Bambu_Tunnel /*tunnel*/,
                             Logger       /*logger*/,
                             void*        /*ctx*/) {
    // Intentionally do NOT store the slicer's logger callback. The
    // slicer's DumpLog (see PrinterFileSystem.cpp:1240) frees every
    // message it receives via the proprietary plugin's
    // Bambu_FreeLogMsg, which only knows how to free pointers minted
    // by libBambuSource's own allocator. Handing it a string literal
    // from our .rodata or a vector<char> from our heap produces an
    // immediate segfault. Our diagnostic fprintf()s cover the same
    // info anyway.
}

} // namespace virtual_tunnel
} // namespace Slic3r
