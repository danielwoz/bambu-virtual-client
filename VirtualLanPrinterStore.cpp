#include "VirtualLanPrinterStore.hpp"

#include "libslic3r/Utils.hpp"

#include <boost/filesystem.hpp>
#include <boost/log/trivial.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <boost/property_tree/ptree.hpp>

#include <fstream>
#include <sstream>

namespace Slic3r {

namespace {
constexpr const char* kDefaultFilename = "virtual_lan_printers.json";
constexpr int         kSchemaVersion   = 1;
} // namespace

VirtualLanPrinterStore::VirtualLanPrinterStore(std::string path) {
    if (path.empty()) {
        boost::filesystem::path p(Slic3r::data_dir());
        p /= kDefaultFilename;
        m_path = p.string();
    } else {
        m_path = std::move(path);
    }
}

std::vector<VirtualLanPrinterStore::Entry>
VirtualLanPrinterStore::load() const {
    std::vector<Entry> out;
    if (!boost::filesystem::exists(m_path)) return out;

    boost::property_tree::ptree root;
    try {
        boost::property_tree::read_json(m_path, root);
    } catch (const std::exception& ex) {
        BOOST_LOG_TRIVIAL(warning)
            << "VirtualLanPrinterStore: parse '" << m_path
            << "' failed: " << ex.what();
        return out;
    }

    const auto printers = root.get_child_optional("printers");
    if (!printers) return out;

    for (const auto& kv : *printers) {
        const auto& node = kv.second;
        Entry e;
        e.dev_id       = node.get<std::string>("dev_id",       "");
        e.dev_name     = node.get<std::string>("dev_name",     "");
        e.lan_ip       = node.get<std::string>("lan_ip",       "");
        e.access_code  = node.get<std::string>("access_code",  "");
        e.printer_type = node.get<std::string>("printer_type", "");
        e.mqtt_port    = node.get<uint16_t>   ("mqtt_port",    0);
        if (e.dev_id.empty()) {
            BOOST_LOG_TRIVIAL(warning)
                << "VirtualLanPrinterStore: skipping entry without dev_id";
            continue;
        }
        out.push_back(std::move(e));
    }
    return out;
}

bool VirtualLanPrinterStore::save(const std::vector<Entry>& entries) const {
    boost::property_tree::ptree root;
    root.put("version", kSchemaVersion);
    boost::property_tree::ptree printers;
    for (const auto& e : entries) {
        boost::property_tree::ptree node;
        node.put("dev_id",       e.dev_id);
        node.put("dev_name",     e.dev_name);
        node.put("lan_ip",       e.lan_ip);
        node.put("access_code",  e.access_code);
        node.put("printer_type", e.printer_type);
        node.put("mqtt_port",    e.mqtt_port);
        printers.push_back(std::make_pair("", std::move(node)));
    }
    root.add_child("printers", std::move(printers));

    // Write to a temp file in the same directory, then rename so a
    // crash mid-write can't leave a half-flushed JSON file in place.
    boost::filesystem::path final_path(m_path);
    boost::filesystem::path tmp_path = final_path;
    tmp_path += ".tmp";
    try {
        boost::filesystem::create_directories(final_path.parent_path());
        {
            std::ofstream os(tmp_path.string());
            if (!os) {
                BOOST_LOG_TRIVIAL(error)
                    << "VirtualLanPrinterStore: can't open " << tmp_path;
                return false;
            }
            boost::property_tree::write_json(os, root);
        }
        boost::filesystem::rename(tmp_path, final_path);
    } catch (const std::exception& ex) {
        BOOST_LOG_TRIVIAL(error)
            << "VirtualLanPrinterStore: save '" << m_path
            << "' failed: " << ex.what();
        boost::system::error_code ec;
        boost::filesystem::remove(tmp_path, ec);
        return false;
    }
    return true;
}

bool VirtualLanPrinterStore::upsert(const Entry& entry) const {
    if (entry.dev_id.empty()) return false;
    auto rows = load();
    bool found = false;
    for (auto& r : rows) {
        if (r.dev_id == entry.dev_id) {
            r = entry;
            found = true;
            break;
        }
    }
    if (!found) rows.push_back(entry);
    return save(rows);
}

bool VirtualLanPrinterStore::remove(const std::string& dev_id) const {
    if (dev_id.empty()) return false;
    auto rows = load();
    const auto before = rows.size();
    rows.erase(
        std::remove_if(rows.begin(), rows.end(),
                       [&](const Entry& e) { return e.dev_id == dev_id; }),
        rows.end());
    if (rows.size() == before) return false;
    return save(rows);
}

} // namespace Slic3r
