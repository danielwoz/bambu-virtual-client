// bambu_virtual_client — VirtualSsdpAliveJson schema contract test (phase 1c).
//
// Pins the JSON shape `DeviceManager::on_machine_alive(std::string)`
// consumes. The schema source-of-truth lives in *both* slicer forks:
//
//   BambuStudio-bridge   src/slic3r/GUI/DeviceCore/DevManager.cpp
//                        DeviceManager::on_machine_alive  (line ~116)
//   OrcaSlicer-bridge    src/slic3r/GUI/DeviceCore/DevManager.cpp
//                        DeviceManager::on_machine_alive  (line ~168)
//
// Both slicers pull the same seven required keys + the same two
// optional keys, so a single golden file pins both consumers.
//
// VirtualSsdpDiscovery.cpp itself transitively depends on the slicer
// (GUI_App.hpp, DevManager.h, wxWidgets) and is excluded from the
// standalone library build. The JSON-building logic was therefore
// split into the pure helper `VirtualSsdpAliveJson.{hpp,cpp}` so this
// test can exercise the contract without dragging the slicer in.
//
// Mirrors the BambuStudio-bridge tests/bridge/MqttFramingTest.cpp
// style: no third-party framework, a single int main() with a fail
// counter; exit code == number of failed assertions.

#include "VirtualSsdpAliveJson.hpp"

#include <nlohmann/json.hpp>

#include <cstdio>
#include <fstream>
#include <set>
#include <sstream>
#include <string>

#ifndef BVC_TEST_FIXTURES_DIR
#  error "BVC_TEST_FIXTURES_DIR must be supplied by CMake."
#endif

using nlohmann::json;
using Slic3r::AliveInfo;
using Slic3r::build_alive_json;

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
        std::fprintf(stderr,
                     "FAIL %s\n  got:  \"%s\"\n  want: \"%s\"\n",
                     what, got.c_str(), want.c_str());
    }
}

std::string load_fixture(const char* name) {
    std::string path = std::string(BVC_TEST_FIXTURES_DIR) + "/" + name;
    std::ifstream f(path);
    if (!f) {
        std::fprintf(stderr, "FAIL fixture not found: %s\n", path.c_str());
        ++g_fails;
        return "{}";
    }
    std::ostringstream os;
    os << f.rdbuf();
    return os.str();
}

// Order-independent structural comparison: nlohmann::json's operator==
// already does deep value-equality without caring about key insertion
// order (it sorts internally by key in `object`). Wrap with a verbose
// diff so failures point at the offending key.
void expect_json_equal(const char* what,
                       const json& got,
                       const json& want) {
    if (got == want) return;
    ++g_fails;
    std::fprintf(stderr,
                 "FAIL %s\n  got:  %s\n  want: %s\n",
                 what, got.dump().c_str(), want.dump().c_str());
}

void expect_json_not_equal(const char* what,
                           const json& got,
                           const json& want) {
    if (got != want) return;
    ++g_fails;
    std::fprintf(stderr,
                 "FAIL %s (expected NOT equal)\n  both: %s\n",
                 what, got.dump().c_str());
}

std::set<std::string> key_set(const json& j) {
    std::set<std::string> s;
    if (!j.is_object()) return s;
    for (auto it = j.begin(); it != j.end(); ++it) s.insert(it.key());
    return s;
}

// ---------------------------------------------------------------------------
// 1. Full-fields golden — the canonical "everything populated" shape.
//    Exercises every required + optional key, plus the explicit (non-
//    defaulted) connect_type / bind_state path.

AliveInfo full_input() {
    AliveInfo info;
    info.dev_name     = "Virtual H2D Lab";
    info.dev_id       = "FFFF1234567890";
    info.dev_ip       = "192.0.2.42";
    info.dev_type     = "H2D";
    info.dev_signal   = "-50dBm";
    info.connect_type = "lan";
    info.bind_state   = "free";
    info.sec_link     = "secure";
    info.ssdp_version = "01.06.00.00";
    return info;
}

void test_full_matches_golden() {
    const std::string out = build_alive_json(full_input());
    const json got  = json::parse(out);
    const json want = json::parse(load_fixture("ssdp_alive_golden.json"));
    expect_json_equal("full AliveInfo round-trips to golden", got, want);

    // Key-set equality (defends against silent additions/removals).
    const auto got_keys  = key_set(got);
    const auto want_keys = key_set(want);
    expect_true("full output key-set equals golden key-set",
                got_keys == want_keys);

    // Spell out the schema explicitly so a mass golden-file edit
    // doesn't silently drift the contract — each required key must
    // appear by name in this test source.
    expect_true("required key dev_name present",     got.contains("dev_name"));
    expect_true("required key dev_id present",       got.contains("dev_id"));
    expect_true("required key dev_ip present",       got.contains("dev_ip"));
    expect_true("required key dev_type present",     got.contains("dev_type"));
    expect_true("required key dev_signal present",   got.contains("dev_signal"));
    expect_true("required key connect_type present", got.contains("connect_type"));
    expect_true("required key bind_state present",   got.contains("bind_state"));
    expect_true("optional key sec_link present",     got.contains("sec_link"));
    expect_true("optional key ssdp_version present", got.contains("ssdp_version"));

    // Every value in the required set is a JSON string (DeviceManager
    // calls .get<std::string>() unconditionally).
    expect_true("dev_name is string",     got["dev_name"].is_string());
    expect_true("dev_id is string",       got["dev_id"].is_string());
    expect_true("dev_ip is string",       got["dev_ip"].is_string());
    expect_true("dev_type is string",     got["dev_type"].is_string());
    expect_true("dev_signal is string",   got["dev_signal"].is_string());
    expect_true("connect_type is string", got["connect_type"].is_string());
    expect_true("bind_state is string",   got["bind_state"].is_string());
    expect_true("sec_link is string",     got["sec_link"].is_string());
    expect_true("ssdp_version is string", got["ssdp_version"].is_string());
}

// ---------------------------------------------------------------------------
// 2. Minimal-fields golden — the hydrate-from-store / no-SSDP-extras
//    path. dev_signal is empty (carried through as ""), and the two
//    optional keys are absent. connect_type defaults to "lan",
//    bind_state defaults to "free".

AliveInfo minimal_input() {
    AliveInfo info;
    info.dev_name = "Virtual A1";
    info.dev_id   = "FFFFA1B2C3D4E5";
    info.dev_ip   = "10.0.0.7";
    info.dev_type = "A1";
    // dev_signal, connect_type, bind_state, sec_link, ssdp_version
    // intentionally left empty — the builder fills defaults and skips
    // optional keys.
    return info;
}

void test_minimal_matches_golden() {
    const std::string out = build_alive_json(minimal_input());
    const json got  = json::parse(out);
    const json want = json::parse(load_fixture("ssdp_alive_minimal_golden.json"));
    expect_json_equal("minimal AliveInfo round-trips to golden", got, want);

    // Defaults applied:
    expect_eq_str("empty connect_type defaults to 'lan'",
                  got.value("connect_type", ""), "lan");
    expect_eq_str("empty bind_state defaults to 'free'",
                  got.value("bind_state", ""), "free");
    // Required: dev_signal pass-through (empty stays empty — DeviceManager
    // calls .get<string>() on it, so the key MUST be present even if "").
    expect_true("dev_signal present even when empty",
                got.contains("dev_signal"));
    expect_eq_str("dev_signal pass-through (empty)",
                  got.value("dev_signal", "MISSING"), "");
    // Optional fields ARE omitted when empty (DeviceManager probes via
    // j.contains, so absent == not provided).
    expect_true("empty sec_link is omitted",     !got.contains("sec_link"));
    expect_true("empty ssdp_version is omitted", !got.contains("ssdp_version"));
}

// ---------------------------------------------------------------------------
// 3. Required-keys-always-present invariant — never let any required
//    key go missing regardless of how empty the input is.

void test_all_required_keys_always_present() {
    AliveInfo empty;   // every field is "" by default
    const json got = json::parse(build_alive_json(empty));

    static constexpr const char* required[] = {
        "dev_name", "dev_id", "dev_ip", "dev_type",
        "dev_signal", "connect_type", "bind_state",
    };
    for (const char* k : required) {
        std::string what = "all-empty input still emits required key: ";
        what += k;
        expect_true(what.c_str(), got.contains(k));
    }
    // Defaults still kick in on the empty input.
    expect_eq_str("all-empty connect_type defaults to 'lan'",
                  got.value("connect_type", ""), "lan");
    expect_eq_str("all-empty bind_state defaults to 'free'",
                  got.value("bind_state", ""), "free");
}

// ---------------------------------------------------------------------------
// 4. Non-default values for connect_type / bind_state are passed
//    through verbatim (we only fill in when EMPTY — never override).

void test_non_default_passthrough() {
    AliveInfo info = full_input();
    info.bind_state   = "occupied";
    // "farm" is the legacy cloud-mode value DeviceManager rewrites to
    // "lan" on its own; the builder should NOT pre-rewrite it.
    info.connect_type = "farm";
    const json got = json::parse(build_alive_json(info));
    expect_eq_str("explicit bind_state passthrough (occupied)",
                  got.value("bind_state", ""), "occupied");
    expect_eq_str("explicit connect_type passthrough (farm)",
                  got.value("connect_type", ""), "farm");
}

// ---------------------------------------------------------------------------
// 5. Reject / sanity test: mutating an input field MUST drive the
//    output away from the golden. Guards against the assertion getting
//    accidentally short-circuited (e.g. comparing two identical
//    parses of the golden file).

void test_input_drift_breaks_golden_match() {
    AliveInfo a = full_input();
    AliveInfo b = full_input();
    b.dev_id = "FFFFDEADBEEFCAFE";   // mutate one required key

    const json gold = json::parse(load_fixture("ssdp_alive_golden.json"));
    const json ja   = json::parse(build_alive_json(a));
    const json jb   = json::parse(build_alive_json(b));

    expect_json_equal("baseline still matches golden", ja, gold);
    expect_json_not_equal("mutated input no longer matches golden",
                          jb, gold);
    // And the two outputs differ pairwise on the mutated key only.
    expect_json_not_equal("mutated input differs from baseline output",
                          jb, ja);
    expect_true("mutation surfaced on dev_id",
                jb.value("dev_id", "") != ja.value("dev_id", ""));
    // Untouched key — should still match.
    expect_eq_str("untouched key dev_ip survives mutation",
                  jb.value("dev_ip", ""), ja.value("dev_ip", ""));
}

// ---------------------------------------------------------------------------
// 6. Output is a single valid JSON document, no trailing garbage —
//    DeviceManager passes the whole string to nlohmann::json::parse.

void test_output_is_clean_json() {
    const std::string out = build_alive_json(full_input());
    expect_true("output non-empty", !out.empty());
    expect_true("output is an object (starts with '{')",
                !out.empty() && out.front() == '{');
    expect_true("output is an object (ends with '}')",
                !out.empty() && out.back() == '}');
    try {
        auto j = json::parse(out);
        expect_true("output parses as a JSON object", j.is_object());
    } catch (const std::exception& ex) {
        ++g_fails;
        std::fprintf(stderr, "FAIL output failed to parse: %s\n", ex.what());
    }
}

} // namespace

int main() {
    test_full_matches_golden();
    test_minimal_matches_golden();
    test_all_required_keys_always_present();
    test_non_default_passthrough();
    test_input_drift_breaks_golden_match();
    test_output_is_clean_json();

    if (g_fails) {
        std::fprintf(stderr,
                     "VirtualSsdpJsonContractTest: %d assertion(s) failed\n",
                     g_fails);
        return 1;
    }
    std::printf("VirtualSsdpJsonContractTest: ok\n");
    return 0;
}
