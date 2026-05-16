// VirtualFtpsClient implementation. Implicit-TLS FTPS — server expects
// TLS handshake immediately on connect, no AUTH command. Bambu's
// printers and the bridge's FtpsServer both use this shape.
//
// Networking: boost::asio for TCP + DNS resolve. TLS: raw OpenSSL
// (TLS 1.2, verify=false) on top of the asio socket's native_handle().
// This matches the slicer's wider networking style (HttpServer.cpp,
// MKS.cpp, TCPConsole.cpp all use asio TCP) while keeping the existing
// SSL_read/SSL_write logic intact.

#include "VirtualFtpsClient.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include <boost/asio.hpp>
#include <boost/system/error_code.hpp>

#ifdef _WIN32
#  include <winsock2.h>
#  include <ws2tcpip.h>
#else
#  include <sys/socket.h>
#endif

#include <openssl/err.h>
#include <openssl/ssl.h>

namespace Slic3r {
namespace virtual_ftps {

namespace asio = boost::asio;
using asio::ip::tcp;
using boost::system::error_code;

namespace {

// One SSL_CTX shared across uploads in this process. verify=false.
SSL_CTX* g_ctx = nullptr;
std::once_flag g_ctx_once;

SSL_CTX* ensure_ctx() {
    std::call_once(g_ctx_once, []() {
        SSL_load_error_strings();
        OpenSSL_add_ssl_algorithms();
        SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
        if (!ctx) return;
        SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nullptr);
        SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
        g_ctx = ctx;
    });
    return g_ctx;
}

// Establish a synchronous TCP connection to host:port via asio. Returns
// the native socket fd or -1 on failure. The asio socket is released so
// the fd's lifetime is owned by the caller (handed to OpenSSL).
int tcp_connect_asio(const std::string& host, uint16_t port) {
    try {
        asio::io_context io;
        tcp::resolver resolver(io);
        error_code ec;
        auto endpoints = resolver.resolve(host, std::to_string(port), ec);
        if (ec) {
            std::fprintf(stderr,
                "[virtual-ftps] resolve %s:%u failed: %s\n",
                host.c_str(), port, ec.message().c_str());
            return -1;
        }
        tcp::socket sock(io);
        asio::connect(sock, endpoints, ec);
        if (ec) {
            std::fprintf(stderr,
                "[virtual-ftps] connect %s:%u failed: %s\n",
                host.c_str(), port, ec.message().c_str());
            return -1;
        }
        auto native = sock.native_handle();
        error_code rel_ec;
        sock.release(rel_ec);
        return static_cast<int>(native);
    } catch (const std::exception& ex) {
        std::fprintf(stderr,
            "[virtual-ftps] connect %s:%u threw: %s\n",
            host.c_str(), port, ex.what());
        return -1;
    }
}

// Tiny TLS wrapper around an fd. Tracks ownership for RAII close.
struct TlsConn {
    int  fd  = -1;
    SSL* ssl = nullptr;

    ~TlsConn() { close(); }

    bool connect(const std::string& host, uint16_t port) {
        fd = tcp_connect_asio(host, port);
        if (fd < 0) return false;
        SSL_CTX* ctx = ensure_ctx();
        if (!ctx) return false;
        ssl = SSL_new(ctx);
        if (!ssl) return false;
        SSL_set_fd(ssl, fd);
        int rc = SSL_connect(ssl);
        if (rc != 1) {
            int e = SSL_get_error(ssl, rc);
            unsigned long q = ERR_get_error();
            std::fprintf(stderr,
                "[virtual-ftps] SSL_connect %s:%u failed ssl_err=%d "
                "errno=%d (%s) queue=%s\n",
                host.c_str(), port, e, errno, std::strerror(errno),
                q ? ERR_error_string(q, nullptr) : "(empty)");
            return false;
        }
        return true;
    }

    void close() {
        if (ssl) { SSL_shutdown(ssl); SSL_free(ssl); ssl = nullptr; }
        if (fd >= 0) {
#ifdef _WIN32
            ::shutdown(fd, SD_BOTH);
            ::closesocket(fd);
#else
            ::shutdown(fd, SHUT_RDWR);
            ::close(fd);
#endif
            fd = -1;
        }
    }

    // Read until we've seen a complete FTP control reply (one or more
    // CRLF-terminated lines ending with a non-continuation line whose
    // 4th char is space). Returns the full reply text, or "" on error.
    // FTP multi-line replies start with "NNN-" and end with "NNN ".
    std::string read_reply() {
        std::string out;
        std::array<char, 1024> buf{};
        while (true) {
            int n = SSL_read(ssl, buf.data(),
                             static_cast<int>(buf.size()));
            if (n <= 0) return {};
            out.append(buf.data(), buf.data() + n);
            // Check if last line is a complete final line.
            auto eol = out.find_last_of('\n');
            if (eol == std::string::npos) continue;
            // Find the start of that last line.
            auto sol = out.rfind('\n', eol - 1);
            const std::string last =
                out.substr(sol == std::string::npos ? 0 : sol + 1, eol);
            if (last.size() >= 4 && std::isdigit(last[0]) &&
                std::isdigit(last[1]) && std::isdigit(last[2]) &&
                last[3] == ' ') {
                return out;
            }
        }
    }

    bool write_line(const std::string& line) {
        const std::string l = line + "\r\n";
        int off = 0;
        while (off < static_cast<int>(l.size())) {
            int n = SSL_write(ssl, l.data() + off,
                              static_cast<int>(l.size() - off));
            if (n <= 0) return false;
            off += n;
        }
        return true;
    }
};

int reply_code(const std::string& r) {
    if (r.size() < 3 || !std::isdigit(r[0])) return -1;
    return (r[0] - '0') * 100 + (r[1] - '0') * 10 + (r[2] - '0');
}

// Parse `227 Entering Passive Mode (h1,h2,h3,h4,p1,p2)` → ip + port.
bool parse_pasv(const std::string& r, std::string& ip, uint16_t& port) {
    auto lp = r.find('(');
    auto rp = r.find(')', lp == std::string::npos ? 0 : lp);
    if (lp == std::string::npos || rp == std::string::npos) return false;
    const std::string inner = r.substr(lp + 1, rp - lp - 1);
    int a, b, c, d, p1, p2;
    if (std::sscanf(inner.c_str(), "%d,%d,%d,%d,%d,%d",
                    &a, &b, &c, &d, &p1, &p2) != 6) return false;
    char buf[INET_ADDRSTRLEN];
    std::snprintf(buf, sizeof(buf), "%d.%d.%d.%d", a, b, c, d);
    ip   = buf;
    port = static_cast<uint16_t>((p1 << 8) | (p2 & 0xff));
    return true;
}

} // namespace

int upload(const UploadParams& p,
           ProgressFn          progress,
           CancelledFn         cancelled) {
    auto notify = [&](int pct, const std::string& s) {
        if (progress) progress(pct, s);
    };
    auto stop_requested = [&]() {
        return cancelled && cancelled();
    };

    // --- 1. Control channel ----------------------------------------------
    TlsConn ctl;
    notify(1, "Connecting to FTPS");
    if (!ctl.connect(p.host, p.port)) return -1;

    std::string r = ctl.read_reply();
    if (reply_code(r) != 220) {
        std::fprintf(stderr,
            "[virtual-ftps] unexpected welcome: %s\n", r.c_str());
        return -2;
    }

    // USER / PASS
    notify(5, "Authenticating");
    if (!ctl.write_line("USER " + p.user)) return -3;
    r = ctl.read_reply();
    const int c1 = reply_code(r);
    if (c1 == 230) {
        // logged in without password — unusual, accept
    } else if (c1 == 331) {
        if (!ctl.write_line("PASS " + p.pass)) return -3;
        r = ctl.read_reply();
        if (reply_code(r) != 230) {
            std::fprintf(stderr,
                "[virtual-ftps] PASS rejected: %s\n", r.c_str());
            return -4;
        }
    } else {
        std::fprintf(stderr,
            "[virtual-ftps] USER unexpected: %s\n", r.c_str());
        return -4;
    }

    // Binary mode
    if (!ctl.write_line("TYPE I")) return -3;
    r = ctl.read_reply();
    if (reply_code(r) != 200) {
        std::fprintf(stderr,
            "[virtual-ftps] TYPE I rejected: %s\n", r.c_str());
        return -5;
    }

    // PASV
    if (!ctl.write_line("PASV")) return -3;
    r = ctl.read_reply();
    if (reply_code(r) != 227) {
        std::fprintf(stderr,
            "[virtual-ftps] PASV rejected: %s\n", r.c_str());
        return -6;
    }
    std::string  data_ip;
    uint16_t     data_port = 0;
    if (!parse_pasv(r, data_ip, data_port)) {
        std::fprintf(stderr,
            "[virtual-ftps] PASV parse failed: %s\n", r.c_str());
        return -7;
    }
    // Many servers return a useless private IP — fall back to the
    // control channel's IP, which is the one the slicer actually
    // configured.
    if (data_ip.empty() || data_ip == "0.0.0.0") data_ip = p.host;

    // --- 2. Data channel -------------------------------------------------
    notify(10, "Opening data channel");
    TlsConn data;
    if (!data.connect(data_ip, data_port)) return -8;

    // --- 3. STOR ---------------------------------------------------------
    if (stop_requested()) return -9;
    if (!ctl.write_line("STOR " + p.remote_name)) return -3;
    r = ctl.read_reply();
    int c = reply_code(r);
    if (c != 150 && c != 125) {
        std::fprintf(stderr,
            "[virtual-ftps] STOR rejected: %s\n", r.c_str());
        return -10;
    }

    // --- 4. Stream the file ---------------------------------------------
    std::ifstream f(p.local_path, std::ios::binary);
    if (!f) {
        std::fprintf(stderr,
            "[virtual-ftps] cannot open %s: %s\n",
            p.local_path.c_str(), std::strerror(errno));
        return -11;
    }
    f.seekg(0, std::ios::end);
    const auto total = static_cast<std::size_t>(f.tellg());
    f.seekg(0, std::ios::beg);

    std::array<char, 32 * 1024> chunk{};
    std::size_t sent = 0;
    while (f) {
        if (stop_requested()) { data.close(); return -9; }
        f.read(chunk.data(), chunk.size());
        const std::streamsize got = f.gcount();
        if (got <= 0) break;
        int off = 0;
        while (off < got) {
            int n = SSL_write(data.ssl, chunk.data() + off,
                              static_cast<int>(got - off));
            if (n <= 0) {
                std::fprintf(stderr,
                    "[virtual-ftps] data SSL_write failed at %zu/%zu\n",
                    sent + off, total);
                data.close();
                return -12;
            }
            off += n;
        }
        sent += static_cast<std::size_t>(got);
        if (total > 0) {
            const int pct = static_cast<int>(
                10 + (sent * 85 / total));
            notify(std::min(pct, 95), "Uploading");
        }
    }
    data.close();

    // Final reply: 226 Transfer complete (or 250).
    r = ctl.read_reply();
    c = reply_code(r);
    if (c != 226 && c != 250) {
        std::fprintf(stderr,
            "[virtual-ftps] STOR final reply unexpected: %s\n",
            r.c_str());
        return -13;
    }

    ctl.write_line("QUIT");
    ctl.read_reply();
    notify(100, "Upload complete");
    return 0;
}

} // namespace virtual_ftps
} // namespace Slic3r
