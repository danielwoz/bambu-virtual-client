// See StructuredLog.hpp for the rationale.

#include "StructuredLog.hpp"

#include <atomic>
#include <chrono>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <thread>

#include <unistd.h>

namespace Slic3r { namespace bridge { namespace structlog {

namespace {

// ISO-8601 UTC with microsecond precision. Always 27 chars +
// terminator: "YYYY-MM-DDTHH:MM:SS.uuuuuuZ".
void format_iso8601_now(char out[28]) {
    using clock = std::chrono::system_clock;
    const auto now    = clock::now();
    const auto secs   = std::chrono::time_point_cast<std::chrono::seconds>(now);
    const auto usec   = std::chrono::duration_cast<std::chrono::microseconds>(
                            now - secs).count();
    const std::time_t t = clock::to_time_t(secs);
    std::tm tm{};
    ::gmtime_r(&t, &tm);
    std::snprintf(out, 28,
                  "%04d-%02d-%02dT%02d:%02d:%02d.%06ldZ",
                  tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
                  tm.tm_hour, tm.tm_min, tm.tm_sec,
                  static_cast<long>(usec));
}

// pthread_self() as 16 hex chars. We use the address bits of the thread
// handle, which is unique-per-thread on Linux (matches `/proc/self/task`
// directory listings).
void format_tid_hex(char out[17]) {
    auto h    = std::hash<std::thread::id>{}(std::this_thread::get_id());
    std::snprintf(out, 17, "%016llx", static_cast<unsigned long long>(h));
}

// Minimal JSON-string escaper: writes "..." (with the surrounding
// quotes) into `out`. Covers the subset slicers actually emit (ASCII
// + control chars + backslash + dquote + non-printables shown as \uXXXX).
void append_json_string(std::string& out, std::string_view in) {
    out.push_back('"');
    out.reserve(out.size() + in.size() + 2);
    for (char c : in) {
        const auto u = static_cast<unsigned char>(c);
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\b': out += "\\b";  break;
            case '\f': out += "\\f";  break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            default:
                if (u < 0x20) {
                    char esc[8];
                    std::snprintf(esc, sizeof(esc), "\\u%04x", u);
                    out += esc;
                } else {
                    out.push_back(c);
                }
        }
    }
    out.push_back('"');
}

} // namespace

// ---------------------------------------------------------------------------
// Log singleton
// ---------------------------------------------------------------------------

Log& Log::instance() {
    static Log inst;
    return inst;
}

Log::Log() {
    const char* env = std::getenv("BBL_STRUCT_LOG");
    if (!env || !*env) return;
    m_path = env;
    // Append-mode so concurrent processes (slicer + bridge children if
    // they ever share a path) don't truncate each other.
    m_fp = std::fopen(m_path.c_str(), "ae");  // 'e' = O_CLOEXEC
    if (!m_fp) return;
    // Line-buffered: each emit flushes the line to the OS without
    // hitting libc's larger default block buffer.
    std::setvbuf(m_fp, nullptr, _IOLBF, 0);
    m_enabled = true;
    // Boot marker — useful when correlating restarts in a long-lived
    // shared log.
    char ts[28]; format_iso8601_now(ts);
    char tid[17]; format_tid_hex(tid);
    std::fprintf(m_fp,
        "{\"ts\":\"%s\",\"pid\":%ld,\"tid\":\"%s\","
        "\"src\":\"structlog\",\"event\":\"open\",\"path\":\"%s\"}\n",
        ts, static_cast<long>(::getpid()), tid, m_path.c_str());
    std::fflush(m_fp);
}

Log::~Log() {
    if (m_fp) {
        char ts[28]; format_iso8601_now(ts);
        char tid[17]; format_tid_hex(tid);
        std::fprintf(m_fp,
            "{\"ts\":\"%s\",\"pid\":%ld,\"tid\":\"%s\","
            "\"src\":\"structlog\",\"event\":\"close\"}\n",
            ts, static_cast<long>(::getpid()), tid);
        std::fclose(m_fp);
        m_fp = nullptr;
    }
}

void Log::write_line_locked(std::string_view body) {
    if (!m_fp) return;
    std::fwrite(body.data(), 1, body.size(), m_fp);
    std::fputc('\n', m_fp);
    // _IOLBF flushes on \n, but make it explicit so kernel-level fsync
    // is the only thing between us and disk. We don't fsync — that's
    // the kernel's job, and we'd kill log perf for the slicer hot
    // paths if we did.
    std::fflush(m_fp);
}

// ---------------------------------------------------------------------------
// Record builder
// ---------------------------------------------------------------------------

Log::Record::Record(const char* component, const char* event)
    : m_enabled(Log::instance().m_enabled) {
    if (!m_enabled) return;
    char ts[28];  format_iso8601_now(ts);
    char tid[17]; format_tid_hex(tid);
    // We build the record body without the trailing '}' so the builders
    // can append more keys. The dtor closes it.
    m_buf.reserve(160);
    m_buf  = "{\"ts\":\"";
    m_buf += ts;
    m_buf += "\",\"pid\":";
    m_buf += std::to_string(static_cast<long>(::getpid()));
    m_buf += ",\"tid\":\"";
    m_buf += tid;
    m_buf += "\",\"src\":";
    append_json_string(m_buf, component ? std::string_view{component} : "");
    m_buf += ",\"event\":";
    append_json_string(m_buf, event     ? std::string_view{event}     : "");
}

Log::Record::~Record() {
    if (!m_enabled) return;
    m_buf += "}";
    auto& log = Log::instance();
    std::lock_guard<std::mutex> lk(log.m_mu);
    log.write_line_locked(m_buf);
}

void Log::Record::append_key(const char* key) {
    m_buf += ',';
    append_json_string(m_buf, key ? std::string_view{key} : "");
    m_buf += ':';
}

Log::Record& Log::Record::str(const char* key, std::string_view value) {
    if (!m_enabled) return *this;
    append_key(key);
    append_json_string(m_buf, value);
    return *this;
}

Log::Record& Log::Record::num(const char* key, long long value) {
    if (!m_enabled) return *this;
    append_key(key);
    m_buf += std::to_string(value);
    return *this;
}

Log::Record& Log::Record::dbl(const char* key, double value) {
    if (!m_enabled) return *this;
    append_key(key);
    char num[32];
    std::snprintf(num, sizeof(num), "%.6g", value);
    m_buf += num;
    return *this;
}

Log::Record& Log::Record::boolean(const char* key, bool value) {
    if (!m_enabled) return *this;
    append_key(key);
    m_buf += value ? "true" : "false";
    return *this;
}

Log::Record& Log::Record::bytes_prefix_hex(const char*       key,
                                           const void*       bytes,
                                           std::size_t       size,
                                           std::size_t       take) {
    if (!m_enabled) return *this;
    append_key(key);
    m_buf.push_back('"');
    const auto* p = static_cast<const unsigned char*>(bytes);
    const std::size_t n = size < take ? size : take;
    static const char kHex[] = "0123456789abcdef";
    for (std::size_t i = 0; i < n; ++i) {
        m_buf.push_back(kHex[(p[i] >> 4) & 0xF]);
        m_buf.push_back(kHex[(p[i]     ) & 0xF]);
    }
    m_buf.push_back('"');
    return *this;
}

} } } // namespace Slic3r::bridge::structlog
