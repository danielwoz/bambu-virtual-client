// bambu_virtual_client — MqttFraming public-API codec test (phase 1a).
//
// Pins the wire format the slicer client speaks. The submodule's public
// API is intentionally narrower than the bridge's MqttFraming: only
// decode_packet() and encode_publish() are exported, so the varint
// encoder is exercised indirectly via PUBLISH payloads that straddle
// the 0/127/128/16383/16384 byte-count boundaries (those produce 1, 1,
// 2, 2, 3-byte remaining-length encodings respectively).
//
// Mirrors the BambuStudio-bridge tests/bridge/MqttFramingTest.cpp style:
// no third-party framework; a single int main() with a fail counter;
// exit code == number of failed assertions.

#include "MqttFraming.hpp"

#include <cstdint>
#include <cstdio>
#include <iomanip>
#include <sstream>
#include <string>
#include <vector>

using namespace Slic3r::virtual_mqtt;

namespace {

int g_fails = 0;

std::string hex(const std::vector<uint8_t>& v, size_t max = 32) {
    std::ostringstream os;
    const size_t n = v.size() < max ? v.size() : max;
    for (size_t i = 0; i < n; ++i) {
        os << std::hex << std::setw(2) << std::setfill('0')
           << static_cast<int>(v[i]);
        if (i + 1 < n) os << ' ';
    }
    if (v.size() > max) os << " ... (" << std::dec << v.size() << " bytes)";
    return os.str();
}

void expect_true(const char* what, bool ok) {
    if (!ok) {
        ++g_fails;
        std::fprintf(stderr, "FAIL %s\n", what);
    }
}

void expect_eq_bytes(const char* what,
                     const std::vector<uint8_t>& got,
                     const std::vector<uint8_t>& want) {
    if (got != want) {
        ++g_fails;
        std::fprintf(stderr, "FAIL %s\n  got:  %s\n  want: %s\n",
                     what, hex(got).c_str(), hex(want).c_str());
    }
}

// ----- PUBLISH round-trip (the only encoded packet type) -------------------

void test_publish_qos0_roundtrip() {
    const std::string topic = "device/EXAMPLESERIAL01/request";
    const std::string body  = "{\"pushing\":{\"command\":\"pushall\"}}";
    std::vector<uint8_t> payload(body.begin(), body.end());

    auto pkt = encode_publish(topic, payload, /*qos=*/0,
                              /*retain=*/false, /*packet_id=*/0);
    expect_true("PUBLISH QoS0 fixed header byte == 0x30",
                !pkt.empty() && pkt[0] == 0x30);

    auto dec = decode_packet(pkt.data(), pkt.size());
    expect_true("PUB QoS0 decode ok",   dec && dec->error == DecodeError::Ok);
    expect_true("PUB QoS0 type",        dec && dec->type == PacketType::Publish);
    expect_true("PUB QoS0 topic",       dec && dec->publish.topic == topic);
    expect_true("PUB QoS0 qos==0",      dec && dec->publish.qos == 0);
    expect_true("PUB QoS0 no packet_id (qos0 has none)",
                dec && dec->publish.packet_id == 0);
    expect_true("PUB QoS0 payload preserved",
                dec && std::string(dec->publish.payload.begin(),
                                   dec->publish.payload.end()) == body);
    expect_true("PUB QoS0 bytes_consumed == pkt.size()",
                dec && dec->bytes_consumed == pkt.size());
}

void test_publish_qos1_roundtrip() {
    const std::string topic = "device/EXAMPLESERIAL01/report";
    const std::string body  = "hi";
    std::vector<uint8_t> payload(body.begin(), body.end());

    auto pkt = encode_publish(topic, payload, /*qos=*/1, /*retain=*/false,
                              /*packet_id=*/42);
    // QoS1 flag bit (0x02) must be set in the fixed-header low nibble.
    expect_true("PUBLISH QoS1 fixed header byte == 0x32",
                !pkt.empty() && pkt[0] == 0x32);

    auto dec = decode_packet(pkt.data(), pkt.size());
    expect_true("PUB QoS1 decode ok",   dec && dec->error == DecodeError::Ok);
    expect_true("PUB QoS1 qos==1",      dec && dec->publish.qos == 1);
    expect_true("PUB QoS1 packet_id==42",
                dec && dec->publish.packet_id == 42);
}

void test_publish_retain_dup_flags() {
    const std::string topic = "device/abc/x";
    std::vector<uint8_t> payload = {'x'};

    auto retained = encode_publish(topic, payload, 0, /*retain=*/true, 0);
    expect_true("PUBLISH retain bit set in fixed header",
                !retained.empty() && (retained[0] & 0x01) == 0x01);
    auto rdec = decode_packet(retained.data(), retained.size());
    expect_true("PUB retain decoded", rdec && rdec->publish.retain);

    auto dupd = encode_publish(topic, payload, 1, /*retain=*/false,
                               /*packet_id=*/1, /*dup=*/true);
    expect_true("PUBLISH dup bit set in fixed header",
                !dupd.empty() && (dupd[0] & 0x08) == 0x08);
    auto ddec = decode_packet(dupd.data(), dupd.size());
    expect_true("PUB dup decoded", ddec && ddec->publish.dup);
}

// Indirectly exercise the varint encoder by choosing payload sizes that
// land each remaining-length byte-count boundary (1B / 2B / 3B). The
// MQTT 3.1.1 §2.2.3 boundaries are 0-127 (1B), 128-16383 (2B),
// 16384-2097151 (3B).
void test_publish_varint_boundaries() {
    struct C { const char* label; size_t payload_len; size_t expected_rl_bytes; };
    const C cases[] = {
        {"varint 1B: payload 0",       0,      1},
        {"varint 1B: payload boundary 95",  95,     1}, // topic + 2-byte header pushes total to ~127
        {"varint 2B: payload 200",     200,    2},
        {"varint 2B: payload 16000",   16000,  2},
        {"varint 3B: payload 17000",   17000,  3},
    };
    // Topic = "t" (1 char + 2-byte length prefix == 3 bytes variable-header).
    const std::string topic = "t";
    for (const auto& c : cases) {
        std::vector<uint8_t> payload(c.payload_len, 'x');
        auto pkt = encode_publish(topic, payload, 0, false, 0);
        // remaining_length itself is bytes 1..(1+rl_bytes); after that the
        // body is variable-header + payload.
        const size_t expected_total =
            1                                  // fixed header byte
            + c.expected_rl_bytes               // remaining-length varint
            + 2 + topic.size()                  // topic length-prefixed string
            + c.payload_len;                    // payload (QoS0, no packet id)
        expect_true(c.label,
                    pkt.size() == expected_total);

        auto dec = decode_packet(pkt.data(), pkt.size());
        expect_true((std::string(c.label) + " decode").c_str(),
                    dec && dec->error == DecodeError::Ok);
        expect_true((std::string(c.label) + " payload-len").c_str(),
                    dec && dec->publish.payload.size() == c.payload_len);
    }
}

// ----- decode-only packet types --------------------------------------------

void test_connack_decode() {
    // CONNACK accepted, no session-present.
    const uint8_t accepted[]  = {0x20, 0x02, 0x00, 0x00};
    auto a = decode_packet(accepted, sizeof(accepted));
    expect_true("CONNACK accepted decode ok",
                a && a->error == DecodeError::Ok);
    expect_true("CONNACK accepted type",
                a && a->type == PacketType::Connack);
    expect_true("CONNACK bytes_consumed",
                a && a->bytes_consumed == sizeof(accepted));

    // CONNACK not-authorized.
    const uint8_t notauth[]   = {0x20, 0x02, 0x00, 0x05};
    auto n = decode_packet(notauth, sizeof(notauth));
    expect_true("CONNACK NotAuthorized decoded",
                n && n->type == PacketType::Connack &&
                n->error == DecodeError::Ok);
}

void test_puback_decode() {
    // PUBACK pid=42:  fixed=0x40, remaining_len=0x02, pid_hi=0x00, pid_lo=0x2A
    const uint8_t buf[] = {0x40, 0x02, 0x00, 0x2A};
    auto dec = decode_packet(buf, sizeof(buf));
    expect_true("PUBACK decode ok",       dec && dec->error == DecodeError::Ok);
    expect_true("PUBACK type",            dec && dec->type == PacketType::Puback);
    expect_true("PUBACK packet_id==42",   dec && dec->puback.packet_id == 42);
    expect_true("PUBACK bytes_consumed",  dec && dec->bytes_consumed == sizeof(buf));
}

void test_suback_decode() {
    // SUBACK pid=7 one rc=0:  0x90 0x03 0x00 0x07 0x00
    const uint8_t buf[] = {0x90, 0x03, 0x00, 0x07, 0x00};
    auto dec = decode_packet(buf, sizeof(buf));
    expect_true("SUBACK decode ok",     dec && dec->error == DecodeError::Ok);
    expect_true("SUBACK type",          dec && dec->type == PacketType::Suback);
    expect_true("SUBACK bytes_consumed",
                dec && dec->bytes_consumed == sizeof(buf));
}

void test_pingresp_decode() {
    const uint8_t buf[] = {0xD0, 0x00};
    auto dec = decode_packet(buf, sizeof(buf));
    expect_true("PINGRESP decode ok",   dec && dec->error == DecodeError::Ok);
    expect_true("PINGRESP type",        dec && dec->type == PacketType::Pingresp);
    expect_true("PINGRESP bytes_consumed",
                dec && dec->bytes_consumed == sizeof(buf));
}

// ----- error paths ---------------------------------------------------------

void test_truncated_returns_nullopt() {
    // Fixed header claims 16 bytes remaining but we only have 2.
    const uint8_t buf[] = {0x30, 0x10};
    auto dec = decode_packet(buf, sizeof(buf));
    expect_true("truncated returns nullopt", !dec.has_value());
}

void test_truncated_varint_returns_nullopt() {
    // High bit set in the remaining-length byte but no follow-up.
    const uint8_t buf[] = {0x30, 0x80};
    auto dec = decode_packet(buf, sizeof(buf));
    expect_true("truncated varint returns nullopt", !dec.has_value());
}

void test_oversized_varint_rejected() {
    // 5-byte continuation overflows MQTT's 4-byte varint cap.
    const uint8_t buf[] = {0x30, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F};
    auto dec = decode_packet(buf, sizeof(buf));
    expect_true("oversized varint -> LengthOverflow",
                dec && dec->error == DecodeError::LengthOverflow);
}

void test_empty_buffer_is_nullopt() {
    auto dec = decode_packet(nullptr, 0);
    expect_true("empty input returns nullopt", !dec.has_value());
}

} // namespace

int main() {
    test_publish_qos0_roundtrip();
    test_publish_qos1_roundtrip();
    test_publish_retain_dup_flags();
    test_publish_varint_boundaries();
    test_connack_decode();
    test_puback_decode();
    test_suback_decode();
    test_pingresp_decode();
    test_truncated_returns_nullopt();
    test_truncated_varint_returns_nullopt();
    test_oversized_varint_rejected();
    test_empty_buffer_is_nullopt();

    if (g_fails) {
        std::fprintf(stderr, "MqttFramingTest: %d assertion(s) failed\n", g_fails);
        return 1;
    }
    std::printf("MqttFramingTest: ok\n");
    return 0;
}
