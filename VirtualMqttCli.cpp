// bambu_virtual_cli — tiny standalone testbed for the Bambu Bridge
// virtual-printer protocol. Uses the same `Slic3r::VirtualMqttClient`
// the slicer uses, so this binary exercises the exact wire path the
// GUI takes — without the wxWidgets/X11 startup overhead.
//
// Build target: `bambu_virtual_cli` (declared in src/CMakeLists.txt).
// Runtime depends only on OpenSSL and the bridge's `bambu_bridge`
// static lib (for the MQTT framer).
//
// Subcommands:
//   connect <host> <sn> <access>
//       Open a TLS+MQTT session, subscribe to device/<sn>/report,
//       print every inbound PUBLISH to stdout, run until Ctrl-C.
//
//   pushall <host> <sn> <access>
//       Like `connect`, but immediately publishes a
//       `pushing.pushall` request on `device/<sn>/request` so the
//       printer sends a full status snapshot back. Exits after
//       --idle-seconds (default 5) of inbound silence.
//
//   send <host> <sn> <access> <json-payload>
//       Publish a single message on `device/<sn>/request`, listen
//       for inbound for --idle-seconds, then exit.
//
// Flags (apply to all subcommands):
//   --idle-seconds N   exit after N seconds of inbound silence
//                      (default 5; set to 0 to disable timeout, e.g.
//                      for `connect`)
//   --max-print N      truncate printed payloads after N chars
//                      (default 200; full payload is always counted)

#include "VirtualMqttClient.hpp"
#include "VirtualFtpsClient.hpp"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <string>
#include <thread>

namespace {

std::atomic<bool>             g_stop{false};
std::mutex                    g_print_mu;
std::chrono::steady_clock::time_point g_last_inbound;

void usage(const char* prog) {
    std::fprintf(stderr,
        "Usage:\n"
        "  %s connect <host> <sn> <access>\n"
        "  %s pushall <host> <sn> <access>\n"
        "  %s send    <host> <sn> <access> <json-payload>\n"
        "  %s upload  <host> <sn> <access> <local-file> [remote-name]\n"
        "\n"
        "Common flags (any position):\n"
        "  --idle-seconds N    Exit after N seconds of inbound silence.\n"
        "                      Default 5; pass 0 to disable (used for\n"
        "                      `connect` to stay alive until SIGINT).\n"
        "  --max-print N       Truncate printed payloads after N chars.\n"
        "                      Default 200.\n",
        prog, prog, prog, prog);
}

void on_signal(int) { g_stop.store(true); }

void install_signal_handlers() {
#ifdef _WIN32
    // Windows has no sigaction; std::signal does what we need (SIGINT only —
    // there's no SIGTERM equivalent in the CRT, console close fires CTRL_CLOSE_EVENT
    // which we don't currently hook).
    std::signal(SIGINT, on_signal);
#else
    struct sigaction sa{};
    sa.sa_handler = on_signal;
    sigemptyset(&sa.sa_mask);
    ::sigaction(SIGINT,  &sa, nullptr);
    ::sigaction(SIGTERM, &sa, nullptr);
#endif
}

// Print `payload` to stdout with a max-prefix cap. The full size is
// reported regardless of truncation so the operator can tell whether
// the body matters.
void print_payload(const std::string& dev_id,
                   const std::string& topic,
                   const std::string& payload,
                   std::size_t        max_print) {
    std::lock_guard<std::mutex> lk(g_print_mu);
    std::printf("[recv] dev=%s topic=%s len=%zu payload=",
                dev_id.c_str(), topic.c_str(), payload.size());
    if (payload.size() <= max_print) {
        std::fwrite(payload.data(), 1, payload.size(), stdout);
    } else {
        std::fwrite(payload.data(), 1, max_print, stdout);
        std::printf(" …(+%zu more)", payload.size() - max_print);
    }
    std::printf("\n");
    std::fflush(stdout);
}

int parse_idle_seconds(int& argc, char** argv) {
    int idle = -1; // sentinel
    for (int i = 1; i < argc; ) {
        if (std::strcmp(argv[i], "--idle-seconds") == 0 && i + 1 < argc) {
            idle = std::atoi(argv[i + 1]);
            // Shift the array left to remove --idle-seconds <N>.
            for (int j = i; j + 2 < argc; ++j) argv[j] = argv[j + 2];
            argc -= 2;
        } else {
            ++i;
        }
    }
    return idle;
}

int parse_max_print(int& argc, char** argv) {
    int n = 200;
    for (int i = 1; i < argc; ) {
        if (std::strcmp(argv[i], "--max-print") == 0 && i + 1 < argc) {
            n = std::atoi(argv[i + 1]);
            for (int j = i; j + 2 < argc; ++j) argv[j] = argv[j + 2];
            argc -= 2;
        } else {
            ++i;
        }
    }
    return n;
}

} // namespace

int main(int argc, char** argv) {
    if (argc < 2) { usage(argv[0]); return 2; }

    int idle = parse_idle_seconds(argc, argv);
    int max_print = parse_max_print(argc, argv);

    const std::string cmd = argv[1];
    if (cmd != "connect" && cmd != "pushall" &&
        cmd != "send"    && cmd != "upload") {
        usage(argv[0]); return 2;
    }
    if (argc < 5) { usage(argv[0]); return 2; }

    if (cmd == "upload") {
        // upload <host> <sn-unused> <access> <local-file> [remote-name]
        if (argc < 6) { usage(argv[0]); return 2; }
        const std::string host     = argv[2];
        const std::string access   = argv[4];
        const std::string local    = argv[5];
        const char*       slash    = std::strrchr(local.c_str(), '/');
        const std::string default_remote =
            slash ? slash + 1 : local;
        const std::string remote   = (argc >= 7) ? argv[6] : default_remote;

        Slic3r::virtual_ftps::UploadParams up;
        up.host        = host;
        up.user        = "bblp";
        up.pass        = access;
        up.local_path  = local;
        up.remote_name = remote;
        const int rc = Slic3r::virtual_ftps::upload(
            up,
            [](int pct, std::string s) {
            },
            nullptr);
        return rc == 0 ? 0 : 1;
    }

    const std::string host    = argv[2];
    const std::string sn      = argv[3];
    const std::string access  = argv[4];
    std::string user_payload;
    if (cmd == "send") {
        if (argc < 6) { usage(argv[0]); return 2; }
        user_payload = argv[5];
    }

    if (idle < 0) idle = (cmd == "connect") ? 0 : 5;

    install_signal_handlers();

    auto& vc = Slic3r::VirtualMqttClient::instance();

    std::condition_variable connected_cv;
    std::mutex               connected_mu;
    bool                     is_connected = false;
    int                      connect_rc   = -1;
    vc.set_on_local_connect(
        [&](int state, std::string /*dev_id*/, std::string /*msg*/) {
            std::lock_guard<std::mutex> lk(connected_mu);
            connect_rc   = state;
            is_connected = (state == 0);
            connected_cv.notify_all();
        });
    vc.set_on_message(
        [&](std::string dev_id, std::string msg) {
            g_last_inbound = std::chrono::steady_clock::now();
            print_payload(dev_id, "(via callback)", msg,
                          static_cast<std::size_t>(max_print));
        });

    int rc = vc.connect_printer(sn, host, access);
    if (rc != 0) {
        return 1;
    }

    // Wait up to 5s for CONNACK / on_connect callback.
    {
        std::unique_lock<std::mutex> lk(connected_mu);
        connected_cv.wait_for(lk, std::chrono::seconds(5),
                              [&] { return is_connected || g_stop.load(); });
    }
    if (!is_connected) {
        return 1;
    }

    // Optionally fire an outbound message.
    if (cmd == "pushall") {
        const std::string body =
            R"({"pushing":{"sequence_id":"0","command":"pushall"}})";
        int srv = vc.send_message(sn, body, /*qos=*/0);
    } else if (cmd == "send") {
        int srv = vc.send_message(sn, user_payload, /*qos=*/0);
    }

    // Main wait loop.
    g_last_inbound = std::chrono::steady_clock::now();
    while (!g_stop.load()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
        if (idle > 0) {
            const auto now    = std::chrono::steady_clock::now();
            const auto silent = std::chrono::duration_cast<
                std::chrono::seconds>(now - g_last_inbound).count();
            if (silent >= idle) {
                break;
            }
        }
    }

    vc.disconnect_printer(sn);
    return 0;
}
