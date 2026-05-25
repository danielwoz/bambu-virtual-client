// MQTT 3.1.1 packet codec for the virtual-printer client.
// Vendored & pruned from BambuStudio-bridge's MqttFraming.cpp; see header.

#include "MqttFraming.hpp"

#include <cstring>

namespace Slic3r {
namespace virtual_mqtt {

namespace {

struct VarintDecode {
    uint32_t value    = 0;
    size_t   consumed = 0;   // SIZE_MAX = truncated, 0 = overflow
};

size_t encode_varint(uint32_t value, uint8_t out[4]) {
    size_t i = 0;
    do {
        uint8_t byte = value & 0x7F;
        value >>= 7;
        if (value) byte |= 0x80;
        out[i++] = byte;
    } while (value && i < 4);
    return i;
}

VarintDecode decode_varint(const uint8_t* buf, size_t len) {
    VarintDecode r;
    uint32_t multiplier = 1;
    uint32_t value      = 0;
    size_t   i          = 0;
    while (true) {
        if (i >= len) {
            r.consumed = SIZE_MAX;
            return r;
        }
        uint8_t byte = buf[i++];
        value += static_cast<uint32_t>(byte & 0x7F) * multiplier;
        if ((byte & 0x80) == 0) {
            r.value    = value;
            r.consumed = i;
            return r;
        }
        if (i == 4) {
            r.consumed = 0;
            r.value    = 0;
            return r;
        }
        multiplier *= 128;
    }
}

struct StringDecode {
    std::string value;
    size_t      consumed = 0;
};

std::optional<StringDecode> decode_mqtt_string(const uint8_t* buf, size_t len) {
    if (len < 2) return std::nullopt;
    uint16_t slen = static_cast<uint16_t>((buf[0] << 8) | buf[1]);
    if (len < 2u + slen) return std::nullopt;
    StringDecode r;
    r.value.assign(reinterpret_cast<const char*>(buf + 2), slen);
    r.consumed = 2u + slen;
    return r;
}

void append_mqtt_string(std::vector<uint8_t>& out, const std::string& s) {
    uint16_t n = static_cast<uint16_t>(s.size());
    out.push_back(static_cast<uint8_t>((n >> 8) & 0xFF));
    out.push_back(static_cast<uint8_t>(n & 0xFF));
    out.insert(out.end(), s.begin(), s.end());
}

void append_uint16_be(std::vector<uint8_t>& out, uint16_t v) {
    out.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
    out.push_back(static_cast<uint8_t>(v & 0xFF));
}

std::vector<uint8_t> finalize(PacketType type, uint8_t flags,
                              const std::vector<uint8_t>& body) {
    uint8_t hdr0 = static_cast<uint8_t>(
        (static_cast<uint8_t>(type) << 4) | (flags & 0x0F));
    uint8_t rl[4];
    size_t  rl_n = encode_varint(static_cast<uint32_t>(body.size()), rl);

    std::vector<uint8_t> out;
    out.reserve(1 + rl_n + body.size());
    out.push_back(hdr0);
    out.insert(out.end(), rl, rl + rl_n);
    out.insert(out.end(), body.begin(), body.end());
    return out;
}

MqttPacket fail(PacketType type, DecodeError err) {
    MqttPacket p;
    p.type           = type;
    p.error          = err;
    p.bytes_consumed = 0;
    return p;
}

bool decode_publish_body(const uint8_t* body, size_t body_len,
                         uint8_t flags, PublishPacket& out, DecodeError& err) {
    out.dup    = (flags & 0x08) != 0;
    out.qos    = static_cast<uint8_t>((flags >> 1) & 0x03);
    out.retain = (flags & 0x01) != 0;
    if (out.qos > 2) { err = DecodeError::Malformed; return false; }

    auto topic = decode_mqtt_string(body, body_len);
    if (!topic) { err = DecodeError::Truncated; return false; }
    out.topic = std::move(topic->value);
    size_t off = topic->consumed;

    if (out.qos > 0) {
        if (off + 2 > body_len) { err = DecodeError::Truncated; return false; }
        out.packet_id =
            static_cast<uint16_t>((body[off] << 8) | body[off + 1]);
        off += 2;
    } else {
        out.packet_id = 0;
    }

    if (off > body_len) { err = DecodeError::Malformed; return false; }
    out.payload.assign(body + off, body + body_len);
    return true;
}

bool decode_puback_body(const uint8_t* body, size_t body_len,
                        PubackPacket& out, DecodeError& err) {
    if (body_len < 2) { err = DecodeError::Truncated; return false; }
    out.packet_id = static_cast<uint16_t>((body[0] << 8) | body[1]);
    return true;
}

} // namespace

std::vector<uint8_t> encode_publish(const std::string& topic,
                                    const std::vector<uint8_t>& payload,
                                    uint8_t qos, bool retain,
                                    uint16_t packet_id, bool dup) {
    uint8_t flags = 0;
    if (dup    && qos > 0) flags |= 0x08;
    if (qos == 1)          flags |= 0x02;
    if (qos == 2)          flags |= 0x04;
    if (retain)            flags |= 0x01;

    std::vector<uint8_t> body;
    body.reserve(2 + topic.size() + (qos > 0 ? 2 : 0) + payload.size());
    append_mqtt_string(body, topic);
    if (qos > 0) {
        append_uint16_be(body, packet_id);
    }
    body.insert(body.end(), payload.begin(), payload.end());
    return finalize(PacketType::Publish, flags, body);
}

std::optional<MqttPacket> decode_packet(const uint8_t* buf, size_t len) {
    if (len < 2) return std::nullopt;

    const uint8_t header = buf[0];
    const auto    type   = static_cast<PacketType>((header >> 4) & 0x0F);
    const uint8_t flags  = header & 0x0F;

    VarintDecode v = decode_varint(buf + 1, len - 1);
    if (v.consumed == SIZE_MAX) return std::nullopt;
    if (v.consumed == 0) {
        return fail(type, DecodeError::LengthOverflow);
    }

    const size_t header_len = 1 + v.consumed;
    const size_t total_len  = header_len + v.value;
    if (len < total_len) return std::nullopt;

    const uint8_t* body     = buf + header_len;
    const size_t   body_len = v.value;

    MqttPacket p;
    p.type           = type;
    p.bytes_consumed = total_len;

    DecodeError err = DecodeError::Ok;
    switch (type) {
    case PacketType::Publish:
        if (!decode_publish_body(body, body_len, flags, p.publish, err))
            return fail(type, err);
        break;

    case PacketType::Puback:
        if (!decode_puback_body(body, body_len, p.puback, err))
            return fail(type, err);
        break;

    case PacketType::Pingresp:
        if (body_len != 0) return fail(type, DecodeError::ProtocolViolation);
        break;

    case PacketType::Connack:
        // [session_present byte][return_code byte]. We don't expose a
        // typed field — the session loop only cares that we saw a
        // Connack frame so it can fire on_local_connect.
        if (body_len != 2) return fail(type, DecodeError::Malformed);
        break;

    case PacketType::Suback:
        // [packet_id MSB][packet_id LSB][per-filter rc...]. Same — only
        // recognised so the read buffer can advance past it.
        if (body_len < 3) return fail(type, DecodeError::Malformed);
        break;

    case PacketType::Unsuback:
        if (body_len != 2) return fail(type, DecodeError::Malformed);
        break;

    case PacketType::Connect:
    case PacketType::Subscribe:
    case PacketType::Unsubscribe:
    case PacketType::Pingreq:
    case PacketType::Disconnect:
        // Inbound from the client's perspective these aren't expected,
        // but accept them as no-op (advance the buffer cursor).
        break;

    case PacketType::Pubrec:
    case PacketType::Pubrel:
    case PacketType::Pubcomp:
        return fail(type, DecodeError::UnsupportedType);

    default:
        return fail(type, DecodeError::Malformed);
    }

    return p;
}

} // namespace virtual_mqtt
} // namespace Slic3r
