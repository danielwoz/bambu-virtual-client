// MQTT 3.1.1 packet codec for the virtual-printer client.
//
// Vendored from BambuStudio-bridge's `bambu_bridge/server/MqttFraming.{hpp,cpp}`,
// pruned to what VirtualMqttClient needs: a decoder for inbound packets
// (CONNACK / PUBLISH / SUBACK / PUBACK / PINGRESP) and an encoder for
// PUBLISH (everything else VirtualMqttClient hand-encodes inline).
//
// The OrcaSlicer-bridge bridge daemon doesn't live in this repo, so we
// only need the client-side subset; the full codec is small enough that
// keeping decode parity with the bridge is cheap.

#ifndef SLIC3R_VIRTUAL_MQTT_FRAMING_HPP
#define SLIC3R_VIRTUAL_MQTT_FRAMING_HPP

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace Slic3r {
namespace virtual_mqtt {

// Control-packet types per MQTT 3.1.1 §2.2.1.
enum class PacketType : uint8_t {
    Reserved    = 0,
    Connect     = 1,
    Connack     = 2,
    Publish     = 3,
    Puback      = 4,
    Pubrec      = 5,
    Pubrel      = 6,
    Pubcomp     = 7,
    Subscribe   = 8,
    Suback      = 9,
    Unsubscribe = 10,
    Unsuback    = 11,
    Pingreq     = 12,
    Pingresp    = 13,
    Disconnect  = 14,
};

enum class DecodeError {
    Ok                   = 0,
    Truncated            = 1,
    Malformed            = 2,
    UnsupportedType      = 3,
    LengthOverflow       = 4,
    ProtocolViolation    = 5,
};

struct PublishPacket {
    std::string          topic;
    uint16_t             packet_id = 0;
    uint8_t              qos       = 0;
    bool                 retain    = false;
    bool                 dup       = false;
    std::vector<uint8_t> payload;
};

struct PubackPacket {
    uint16_t packet_id = 0;
};

struct MqttPacket {
    PacketType  type  = PacketType::Reserved;
    DecodeError error = DecodeError::Ok;
    size_t      bytes_consumed = 0;

    PublishPacket publish;
    PubackPacket  puback;
};

// Reads exactly one MQTT control packet from the start of `buf`.
// nullopt = truncated (caller buffers more), otherwise check `error`.
std::optional<MqttPacket> decode_packet(const uint8_t* buf, size_t len);

// PUBLISH encoder — the only one VirtualMqttClient needs from this
// module (CONNECT / SUBSCRIBE / DISCONNECT are hand-encoded inline).
std::vector<uint8_t> encode_publish(const std::string& topic,
                                    const std::vector<uint8_t>& payload,
                                    uint8_t  qos,
                                    bool     retain,
                                    uint16_t packet_id,
                                    bool     dup = false);

} // namespace virtual_mqtt
} // namespace Slic3r

#endif // SLIC3R_VIRTUAL_MQTT_FRAMING_HPP
