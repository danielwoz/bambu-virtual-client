// Slicer-side virtual Bambu_Tunnel impl. Plugs into the BambuLib function
// pointers loaded by PrinterFileSystem so that URLs of the form
//     bambu:///virtual/<host>:<port>?dev_id=...&access_code=...
// open a TLS connection to our bridge's `VirtualTunnelServer` instead of
// libBambuSource. Every other URL falls through to the real libBambuSource
// call. See the bridge-side server header for the wire format (4-byte BE
// length-prefixed JSON frames).
//
// Why dispatch at the BambuLib layer rather than higher up:
//   - PrinterFileSystem already holds a Bambu_Tunnel; teaching it about
//     "virtual" vs "real" tunnels would touch every read/write/close site.
//   - The Bambu_Tunnel type is `void*`; we control everything we return
//     from Bambu_Create. By prefixing our allocation with a magic word we
//     can cheaply tell our tunnels apart from libBambuSource's in each
//     wrapper.
//   - The wrappers are stateless C-style trampolines that read the magic
//     and route. Real tunnels pass straight through; virtual tunnels go
//     to functions in this header.

#ifndef SLIC3R_GUI_PRINTER_VIRTUAL_BAMBU_TUNNEL_HPP
#define SLIC3R_GUI_PRINTER_VIRTUAL_BAMBU_TUNNEL_HPP

// Resolved from the consuming slicer's src/slic3r/GUI/Printer/
// include path (supplied to the lib via CMake).
#include "BambuTunnel.h"

#include <cstdint>

namespace Slic3r {
namespace virtual_tunnel {

// Sentinel at the start of every VirtualTunnel allocation. Any function
// the slicer hands a Bambu_Tunnel pointer to can check the first 4 bytes
// to tell ours from libBambuSource's.
constexpr uint32_t kMagic = 0xB16BEE5Cu;

// True iff `t` is a tunnel we minted (first 4 bytes == kMagic). Cheap to
// call from each dispatch trampoline; the magic prefix is at a fixed
// offset so a wrongly-cast pointer at most reads 4 bytes of unrelated
// memory before returning false.
bool is_virtual_tunnel(Bambu_Tunnel t);

// Function implementations called by the dispatch trampolines wired up in
// PrinterFileSystem.cpp's StaticBambuLib::get().
int  Bambu_Create_virtual       (Bambu_Tunnel* out, char const* url);
int  Bambu_Open_virtual         (Bambu_Tunnel t);
int  Bambu_StartStream_virtual  (Bambu_Tunnel t, bool video);
int  Bambu_StartStreamEx_virtual(Bambu_Tunnel t, int type);
int  Bambu_SendMessage_virtual  (Bambu_Tunnel t, int ctrl,
                                 char const* data, int len);
int  Bambu_ReadSample_virtual   (Bambu_Tunnel t, Bambu_Sample* sample);
void Bambu_Close_virtual        (Bambu_Tunnel t);
void Bambu_Destroy_virtual      (Bambu_Tunnel t);
void Bambu_SetLogger_virtual    (Bambu_Tunnel t, Logger logger, void* ctx);

// True iff `url` matches our scheme — the only check Bambu_Create_dispatch
// needs to decide which side handles the open.
bool url_is_virtual(char const* url);

} // namespace virtual_tunnel
} // namespace Slic3r

#endif // SLIC3R_GUI_PRINTER_VIRTUAL_BAMBU_TUNNEL_HPP
