// Bambu virtual client — env-gated JSON-Lines structured log.
//
// Why this exists
// ---------------
//   The free-form OrcaSlicer/BambuStudio log is excellent for human
//   reading but painful for cross-process correlation: figuring out
//   whether a `get_files` MQTT round-trip actually completed means
//   grepping through tens of MB of mixed-component noise and eyeballing
//   timestamps. The bridge daemon already emits machine-parseable
//   events (see [mqtt-broker] UPSTREAM / [lan-uplink] on_publish /
//   [camera-fanout] produced= lines). This module gives the slicer
//   side an equally machine-parseable emit so the two can be joined
//   on dev_id + topic + payload digest.
//
// Format
// ------
//   One JSON object per line, written to the path in BBL_STRUCT_LOG.
//   Every record carries:
//     - ts   : ISO-8601 UTC with microsecond precision
//     - pid  : process id (the OS pid, not wx's)
//     - tid  : posix thread id formatted as 16-digit hex
//     - src  : short component name (e.g. "virtual-mqtt", "ftps-client")
//     - event: short event name (e.g. "publish_send", "stor_reply")
//   Event-specific keys are appended via the builder methods.
//
// Activation
// ----------
//   Unset BBL_STRUCT_LOG  → all macros expand to a no-op temporary
//                            (one bool check + immediate destruction).
//   BBL_STRUCT_LOG=<path> → records are line-buffered + fsync()'d to
//                            <path> on every emit. Append-only; safe
//                            to share the path across child processes
//                            because each emit takes a process-wide
//                            mutex while writing the line.
//
// Usage
// -----
//     BBL_LOG("virtual-mqtt", "publish_send")
//         .str("dev_id", dev_id)
//         .str("topic",  topic)
//         .num("qos",    qos)
//         .num("bytes",  payload.size());
//
//   Builder methods return `Record&` so chains compose; the record's
//   destructor flushes the line at the end of the full-expression. Safe
//   to call from any thread. Builder copies inputs into an internal
//   buffer — caller can free its strings immediately.
//
// Cost
// ----
//   Disabled: one bool compare in the Record ctor and dtor. No JSON
//   formatting, no allocation beyond the (~64-byte) Record itself.
//   Enabled: one mutex acquire per emit, one writev() of the line, one
//   fsync(). Fine for slicer-rate events (low hundreds per second tops).

#ifndef BBL_VIRTUAL_CLIENT_STRUCTURED_LOG_HPP
#define BBL_VIRTUAL_CLIENT_STRUCTURED_LOG_HPP

#include <cstdint>
#include <cstdio>
#include <mutex>
#include <string>
#include <string_view>

namespace Slic3r { namespace bridge { namespace structlog {

class Log {
public:
    static Log& instance();

    // True if BBL_STRUCT_LOG was set and the file opened. When false,
    // every Record below short-circuits to a no-op.
    bool enabled() const { return m_enabled; }

    // Builder for one record. Lifetime is the enclosing full-expression
    // — the destructor formats and writes the JSON line.
    class Record {
    public:
        Record(const char* component, const char* event);
        ~Record();

        // Builders. All return *this so calls chain. When the log is
        // disabled, every call is a no-op.
        Record& str (const char* key, std::string_view value);
        Record& num (const char* key, long long value);
        Record& dbl (const char* key, double value);
        Record& boolean(const char* key, bool value);
        // Hex digest helper: prints the first `take` bytes of `bytes`
        // as lowercase hex into the record. Useful for payload prefixes
        // so the bridge log can be joined by content shape.
        Record& bytes_prefix_hex(const char* key,
                                 const void* bytes,
                                 std::size_t size,
                                 std::size_t take = 16);

        // No copies — the temporary should die at end-of-expression.
        Record(const Record&)            = delete;
        Record& operator=(const Record&) = delete;
        // Allow moves so functions can return them (rare; mostly the
        // temporary is consumed in-place).
        Record(Record&&)             = default;
        Record& operator=(Record&&)  = default;

    private:
        bool        m_enabled;
        std::string m_buf;   // open-and-append JSON body fragments
        // Appends `, "key":` to m_buf without copying the surrounding
        // JSON object braces. Caller appends the value-formatting bytes.
        void append_key(const char* key);
    };

private:
    Log();
    ~Log();
    Log(const Log&)            = delete;
    Log& operator=(const Log&) = delete;

    void write_line_locked(std::string_view body);

    bool        m_enabled = false;
    std::mutex  m_mu;
    std::FILE*  m_fp      = nullptr;
    std::string m_path;

    friend class Record;
};

} } } // namespace Slic3r::bridge::structlog

// Public macro. Returns a temporary Record by value so the caller can
// chain builders. The temporary's destructor emits the line at the end
// of the full-expression.
//
//   BBL_LOG("ftps-client", "stor_reply").num("code", 226).str("msg", line);
//
// When BBL_STRUCT_LOG is unset, the constructor flips the no-op bit and
// every builder method short-circuits, so the cost is one ctor + one
// dtor of an ~80-byte stack object.
#define BBL_LOG(component, event_name) \
    ::Slic3r::bridge::structlog::Log::Record((component), (event_name))

#endif // BBL_VIRTUAL_CLIENT_STRUCTURED_LOG_HPP
