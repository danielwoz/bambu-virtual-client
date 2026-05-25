// bambu_virtual_client — VirtualLanPrinterStore persist/hydrate test
// (phase 1d).
//
// Exercises the JSON-on-disk persistence the slicer uses to remember
// FFFF (virtual) printers between launches. The standalone build of
// the submodule has no libslic3r/Slic3r::data_dir() — we drive the
// store via the in_dir() factory introduced in this phase, which lets
// the test point each subtest at a unique /tmp directory.
//
// Style matches tests/MqttFramingTest.cpp: no third-party framework,
// a single int main() with a fail counter, exit code == number of
// failed assertions.

#include "VirtualLanPrinterStore.hpp"

#include <boost/filesystem.hpp>

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <string>
#include <sys/types.h>
#include <unistd.h>
#include <vector>

using Slic3r::VirtualLanPrinterStore;

namespace {

int g_fails = 0;

void expect_true(const char* what, bool ok) {
    if (!ok) {
        ++g_fails;
        std::fprintf(stderr, "FAIL %s\n", what);
    }
}

void expect_eq_str(const char* what,
                   const std::string& got,
                   const std::string& want) {
    if (got != want) {
        ++g_fails;
        std::fprintf(stderr, "FAIL %s\n  got:  \"%s\"\n  want: \"%s\"\n",
                     what, got.c_str(), want.c_str());
    }
}

void expect_eq_size(const char* what, size_t got, size_t want) {
    if (got != want) {
        ++g_fails;
        std::fprintf(stderr, "FAIL %s\n  got:  %zu\n  want: %zu\n",
                     what, got, want);
    }
}

// Per-subtest temp directory. Each subtest gets a fresh one so failures
// don't cross-contaminate. Cleaned up via RAII.
struct TempDir {
    boost::filesystem::path path;
    explicit TempDir(int n) {
        const auto pid = static_cast<long>(::getpid());
        char buf[128];
        std::snprintf(buf, sizeof(buf),
                      "/tmp/bvc-lanstore-test-%ld-%d", pid, n);
        path = buf;
        boost::system::error_code ec;
        boost::filesystem::remove_all(path, ec);
        boost::filesystem::create_directories(path, ec);
    }
    ~TempDir() {
        boost::system::error_code ec;
        boost::filesystem::remove_all(path, ec);
    }
    std::string str() const { return path.string(); }
};

// Locate an entry by dev_id; returns nullptr if not present so the
// caller can fail the subtest with a useful message.
const VirtualLanPrinterStore::Entry*
find_entry(const std::vector<VirtualLanPrinterStore::Entry>& rows,
           const std::string& dev_id) {
    auto it = std::find_if(rows.begin(), rows.end(),
                           [&](const VirtualLanPrinterStore::Entry& e) {
                               return e.dev_id == dev_id;
                           });
    return it == rows.end() ? nullptr : &*it;
}

VirtualLanPrinterStore::Entry make_entry(const std::string& id,
                                        const std::string& name,
                                        const std::string& ip,
                                        const std::string& code,
                                        const std::string& type,
                                        uint16_t port) {
    VirtualLanPrinterStore::Entry e;
    e.dev_id       = id;
    e.dev_name     = name;
    e.lan_ip       = ip;
    e.access_code  = code;
    e.printer_type = type;
    e.mqtt_port    = port;
    return e;
}

void expect_entries_equal(const char* tag,
                          const VirtualLanPrinterStore::Entry& got,
                          const VirtualLanPrinterStore::Entry& want) {
    expect_eq_str((std::string(tag) + " dev_id").c_str(),
                  got.dev_id, want.dev_id);
    expect_eq_str((std::string(tag) + " dev_name").c_str(),
                  got.dev_name, want.dev_name);
    expect_eq_str((std::string(tag) + " lan_ip").c_str(),
                  got.lan_ip, want.lan_ip);
    expect_eq_str((std::string(tag) + " access_code").c_str(),
                  got.access_code, want.access_code);
    expect_eq_str((std::string(tag) + " printer_type").c_str(),
                  got.printer_type, want.printer_type);
    if (got.mqtt_port != want.mqtt_port) {
        ++g_fails;
        std::fprintf(stderr, "FAIL %s mqtt_port\n  got:  %u\n  want: %u\n",
                     tag, got.mqtt_port, want.mqtt_port);
    }
}

// ----- Subtest 1: empty round-trip -----------------------------------------

void test_empty_roundtrip() {
    TempDir dir(1);
    VirtualLanPrinterStore store = VirtualLanPrinterStore::in_dir(dir.str());

    expect_true("1: save empty",
                store.save(std::vector<VirtualLanPrinterStore::Entry>{}));
    // File should exist after save (atomic-rename leaves it in place).
    expect_true("1: file present after empty save",
                boost::filesystem::exists(store.path()));

    VirtualLanPrinterStore reload = VirtualLanPrinterStore::in_dir(dir.str());
    auto rows = reload.load();
    expect_eq_size("1: empty reload size", rows.size(), 0);
}

// ----- Subtest 2: one entry round-trip -------------------------------------

void test_single_entry_roundtrip() {
    TempDir dir(2);
    VirtualLanPrinterStore store = VirtualLanPrinterStore::in_dir(dir.str());

    auto want = make_entry("FFFF0123456789A", "Bridge Bay 1",
                           "10.0.0.42", "12345678", "N2S", 8884);
    expect_true("2: save one",
                store.save({want}));

    VirtualLanPrinterStore reload = VirtualLanPrinterStore::in_dir(dir.str());
    auto rows = reload.load();
    expect_eq_size("2: reload size", rows.size(), 1);
    if (rows.size() == 1) {
        expect_entries_equal("2:", rows[0], want);
    }
}

// ----- Subtest 3: multi-entry round-trip -----------------------------------

void test_multi_entry_roundtrip() {
    TempDir dir(3);
    VirtualLanPrinterStore store = VirtualLanPrinterStore::in_dir(dir.str());

    std::vector<VirtualLanPrinterStore::Entry> want = {
        make_entry("FFFFAAAAAAAA001", "Printer A", "10.1.0.1", "AAAA1111", "N2S",   8883),
        make_entry("FFFFBBBBBBBB002", "Printer B", "10.1.0.2", "BBBB2222", "O1S",   8884),
        make_entry("FFFFCCCCCCCC003", "Printer C", "10.1.0.3", "CCCC3333", "O1D",   8885),
        make_entry("FFFFDDDDDDDD004", "Printer D", "10.1.0.4", "DDDD4444", "H2S",   8886),
        make_entry("FFFFEEEEEEEE005", "Printer E", "10.1.0.5", "EEEE5555", "H2D",   8887),
    };
    expect_true("3: save five", store.save(want));

    VirtualLanPrinterStore reload = VirtualLanPrinterStore::in_dir(dir.str());
    auto rows = reload.load();
    expect_eq_size("3: reload size", rows.size(), 5);

    for (const auto& w : want) {
        const auto* g = find_entry(rows, w.dev_id);
        if (!g) {
            ++g_fails;
            std::fprintf(stderr, "FAIL 3: missing dev_id %s\n",
                         w.dev_id.c_str());
            continue;
        }
        expect_entries_equal(("3:" + w.dev_id).c_str(), *g, w);
    }
}

// ----- Subtest 4: update existing entry ------------------------------------

void test_update_existing_entry() {
    TempDir dir(4);
    VirtualLanPrinterStore store = VirtualLanPrinterStore::in_dir(dir.str());

    auto a = make_entry("FFFFAA00000001A", "A-original", "10.2.0.1", "AAAA1111", "N2S", 8883);
    auto b = make_entry("FFFFBB00000002B", "B-untouched", "10.2.0.2", "BBBB2222", "O1S", 8884);
    auto c = make_entry("FFFFCC00000003C", "C-untouched", "10.2.0.3", "CCCC3333", "O1D", 8885);
    expect_true("4: save three", store.save({a, b, c}));

    // Update entry B via upsert() (matches the slicer's real flow).
    auto b_updated = b;
    b_updated.dev_name    = "B-updated";
    b_updated.lan_ip      = "10.2.0.222";
    b_updated.access_code = "ZZZZ9999";
    b_updated.mqtt_port   = 18884;
    expect_true("4: upsert update", store.upsert(b_updated));

    VirtualLanPrinterStore reload = VirtualLanPrinterStore::in_dir(dir.str());
    auto rows = reload.load();
    expect_eq_size("4: still three", rows.size(), 3);

    const auto* got_a = find_entry(rows, a.dev_id);
    const auto* got_b = find_entry(rows, b.dev_id);
    const auto* got_c = find_entry(rows, c.dev_id);
    expect_true("4: A still present", got_a != nullptr);
    expect_true("4: B still present", got_b != nullptr);
    expect_true("4: C still present", got_c != nullptr);
    if (got_a) expect_entries_equal("4:A", *got_a, a);
    if (got_b) expect_entries_equal("4:B", *got_b, b_updated);
    if (got_c) expect_entries_equal("4:C", *got_c, c);
}

// ----- Subtest 5: remove entry ---------------------------------------------

void test_remove_entry() {
    TempDir dir(5);
    VirtualLanPrinterStore store = VirtualLanPrinterStore::in_dir(dir.str());

    auto a = make_entry("FFFFAA00000005A", "A", "10.3.0.1", "AAAA1111", "N2S", 8883);
    auto b = make_entry("FFFFBB00000005B", "B", "10.3.0.2", "BBBB2222", "O1S", 8884);
    auto c = make_entry("FFFFCC00000005C", "C", "10.3.0.3", "CCCC3333", "O1D", 8885);
    expect_true("5: save three", store.save({a, b, c}));

    expect_true("5: remove B returns true", store.remove(b.dev_id));
    // Second remove of the same dev_id is a no-op and returns false.
    expect_true("5: remove B again returns false",
                !store.remove(b.dev_id));

    VirtualLanPrinterStore reload = VirtualLanPrinterStore::in_dir(dir.str());
    auto rows = reload.load();
    expect_eq_size("5: size after remove", rows.size(), 2);
    expect_true("5: B is gone",   find_entry(rows, b.dev_id) == nullptr);
    expect_true("5: A remains",   find_entry(rows, a.dev_id) != nullptr);
    expect_true("5: C remains",   find_entry(rows, c.dev_id) != nullptr);
}

// ----- Subtest 6: corrupted JSON file recovers ------------------------------

void test_corrupted_file_recovery() {
    TempDir dir(6);
    VirtualLanPrinterStore store = VirtualLanPrinterStore::in_dir(dir.str());

    // Hand-write garbage at the path the store would otherwise read.
    {
        std::ofstream os(store.path());
        os << "{ this is not json \n  \"and\": [ unterminated";
    }
    expect_true("6: garbage file exists pre-load",
                boost::filesystem::exists(store.path()));

    // load() must not throw; must return an empty vector.
    auto rows = store.load();
    expect_eq_size("6: corrupted -> empty", rows.size(), 0);

    // The store should still be writable after observing the garbage.
    auto e = make_entry("FFFF99900000001", "Recovered", "10.4.0.1",
                        "99999999", "N2S", 0);
    expect_true("6: save after garbage", store.save({e}));

    VirtualLanPrinterStore reload = VirtualLanPrinterStore::in_dir(dir.str());
    auto rows2 = reload.load();
    expect_eq_size("6: reload size", rows2.size(), 1);
    if (rows2.size() == 1) {
        expect_entries_equal("6:", rows2[0], e);
    }
}

// ----- Subtest 7: missing file behaves as empty -----------------------------

void test_missing_file() {
    TempDir dir(7);
    // Don't pre-create anything; the path resolves under the temp dir but
    // virtual_lan_printers.json doesn't exist yet.
    VirtualLanPrinterStore store = VirtualLanPrinterStore::in_dir(dir.str());

    expect_true("7: file is absent pre-load",
                !boost::filesystem::exists(store.path()));

    // load() on a missing file must not throw and must return empty.
    auto rows = store.load();
    expect_eq_size("7: missing -> empty", rows.size(), 0);

    // remove() on a missing file: nothing to drop -> false, no crash.
    expect_true("7: remove on missing returns false",
                !store.remove("FFFFANYTHING001"));
}

} // namespace

int main() {
    test_empty_roundtrip();
    test_single_entry_roundtrip();
    test_multi_entry_roundtrip();
    test_update_existing_entry();
    test_remove_entry();
    test_corrupted_file_recovery();
    test_missing_file();

    if (g_fails) {
        std::fprintf(stderr,
                     "VirtualLanPrinterStorePersistTest: %d assertion(s) failed\n",
                     g_fails);
        return 1;
    }
    std::printf("VirtualLanPrinterStorePersistTest: ok\n");
    return 0;
}
