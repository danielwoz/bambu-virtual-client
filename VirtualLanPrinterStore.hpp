// Persistence layer for virtual LAN printers.
//
// The slicer's existing "Input access code" flow creates a MachineObject
// in memory via DeviceManager::insert_local_device, but that object
// vanishes on slicer restart — the user has to re-type the serial,
// access code and pick the model every single session. For FFFF-prefix
// virtual dev_ids (bridge-served) that's especially painful because the
// data is also stored on the bridge side; the slicer just needs a
// pointer to it.
//
// This store keeps a plaintext JSON file at
//   <data_dir>/virtual_lan_printers.json
// containing one entry per virtual printer the slicer has ever
// connected to. Load happens once at GUI_App startup (after the
// DeviceManager is constructed); upsert happens after a successful
// `insert_local_device` for a FFFF dev_id; remove happens when the user
// clicks the unbind/disconnect button on a virtual LAN printer.
//
// Why a dedicated file (vs reusing app_config's ini): JSON is the
// natural shape for a list of records, hand-editable, easy to delete
// rows from. The slicer's own access_code persistence already lives in
// app_config and we leave that alone.

#ifndef SLIC3R_VIRTUAL_LAN_PRINTER_STORE_HPP
#define SLIC3R_VIRTUAL_LAN_PRINTER_STORE_HPP

#include <cstdint>
#include <string>
#include <vector>

namespace Slic3r {

class VirtualLanPrinterStore {
public:
    struct Entry {
        std::string dev_id;         // FFFF + 11 hex chars
        std::string dev_name;       // user-facing label
        std::string lan_ip;         // bridge IP (the host this slicer talked to)
        std::string access_code;    // 8-char access code from the real printer
        std::string printer_type;   // model id e.g. "N2S" / "O1S" / "O1D"
        // MQTT port the bridge advertises for this printer (one per device).
        // Populated from the SSDP LOCATION header. 0 = unknown; the
        // VirtualMqttClient port resolver falls back to 8883 in that case.
        uint16_t    mqtt_port = 0;
    };

    // Path defaults to <data_dir>/virtual_lan_printers.json. Override
    // mainly for unit tests.
    explicit VirtualLanPrinterStore(std::string path = {});

    // Build a store that lives at <data_dir>/virtual_lan_printers.json
    // without consulting Slic3r::data_dir(). Lets the standalone build
    // (which has no libslic3r) and unit tests pick a directory without
    // having to hard-code the filename.
    static VirtualLanPrinterStore in_dir(const std::string& data_dir);

    // Returns the persisted entries; empty vector if the file doesn't
    // exist or is malformed. Never throws — logs malformed lines via
    // BOOST_LOG_TRIVIAL and returns whatever was parseable.
    std::vector<Entry> load() const;

    // Replace the on-disk list. Atomic on POSIX (write to tmp + rename).
    bool save(const std::vector<Entry>& entries) const;

    // Convenience: load → match-or-append-on-dev_id → save.
    bool upsert(const Entry& entry) const;

    // Convenience: load → drop matching dev_id → save. Returns true if
    // an entry was removed.
    bool remove(const std::string& dev_id) const;

    const std::string& path() const { return m_path; }

private:
    std::string m_path;
};

} // namespace Slic3r

#endif // SLIC3R_VIRTUAL_LAN_PRINTER_STORE_HPP
