// VirtualFtpsClient — implicit-TLS FTPS client used by the slicer to
// upload print jobs to a Bambu Bridge's virtual-printer FTPS port
// (bridge IP, port 39990 by default, verify=false). NetworkAgent
// routes start_send_gcode_to_sdcard for FFFF-prefixed dev_ids here
// instead of through the proprietary plugin (whose cert validation
// against Bambu's CA would reject the bridge's self-signed cert).
//
// Scope: one synchronous upload at a time. The slicer's send-job
// callbacks expect a sync return — we drive the FTPS state machine
// inline.

#ifndef SLIC3R_VIRTUAL_FTPS_CLIENT_HPP
#define SLIC3R_VIRTUAL_FTPS_CLIENT_HPP

#include <cstdint>
#include <functional>
#include <string>

namespace Slic3r {

namespace virtual_ftps {

// 0 = success, negative = failure code (mirrors plugin convention).
// progress() is invoked with (percent 0-100, status string).
// cancelled() returning true aborts the transfer ASAP.
using ProgressFn  = std::function<void(int, std::string)>;
using CancelledFn = std::function<bool()>;

struct UploadParams {
    std::string host;
    uint16_t    port = 39990;      // bridge's default high FTPS port
    std::string user = "bblp";
    std::string pass;              // printer access code
    std::string local_path;        // file on disk to send
    std::string remote_name;       // STOR target (basename on the bridge)
};

int upload(const UploadParams& p,
           ProgressFn  progress  = nullptr,
           CancelledFn cancelled = nullptr);

} // namespace virtual_ftps
} // namespace Slic3r

#endif // SLIC3R_VIRTUAL_FTPS_CLIENT_HPP
