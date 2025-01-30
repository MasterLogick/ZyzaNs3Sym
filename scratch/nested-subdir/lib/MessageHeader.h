#ifndef ZYZZYVA_A_LIBZYZA_MESSAGEHEADER_H
#define ZYZZYVA_A_LIBZYZA_MESSAGEHEADER_H
#include <cstdint>

namespace zyza
{
struct MessageHeader
{
    uint32_t messageSize;
    uint16_t senderIdx;
    uint16_t messageType;
    uint64_t msgId;
};

enum class MessageType
{
    REQUEST = 1,
    RESPONSE = 2,
    NEXT_ROUND_PROPOSAL = 3,
    ROUND_ACK = 4,
    ACCEPT_QUORUM_CERTIFICATE = 5,
    REDIRECT_REQUEST = 6,
    FALLBACK_ALERT = 7,
    QUORUM_DROP_REQUEST = 8,
    QUORUM_DROP_RESPONSE = 9,
    RECOVERY = 10,
    NETWORK_STATUS_REQUEST = 11,
    NETWORK_STATUS_RESPONSE = 12,
    RESEND_CHAIN_REQUEST = 13,
    RESEND_CHAIN_RESPONSE = 14,
};

constexpr const char*
messageTypeToString(MessageType type)
{
    switch (type)
    {
    case MessageType::REQUEST:
        return "REQUEST";
    case MessageType::RESPONSE:
        return "RESPONSE";
    case MessageType::NEXT_ROUND_PROPOSAL:
        return "NEXT_ROUND_PROPOSAL";
    case MessageType::ROUND_ACK:
        return "ROUND_ACK";
    case MessageType::ACCEPT_QUORUM_CERTIFICATE:
        return "ACCEPT_QUORUM_CERTIFICATE";
    case MessageType::REDIRECT_REQUEST:
        return "REDIRECT_REQUEST";
    case MessageType::FALLBACK_ALERT:
        return "FALLBACK_ALERT";
    case MessageType::QUORUM_DROP_REQUEST:
        return "QUORUM_DROP_REQUEST";
    case MessageType::QUORUM_DROP_RESPONSE:
        return "QUORUM_DROP_RESPONSE";
    case MessageType::RECOVERY:
        return "RECOVERY";
    case MessageType::NETWORK_STATUS_REQUEST:
        return "NETWORK_STATUS_REQUEST";
    case MessageType::NETWORK_STATUS_RESPONSE:
        return "NETWORK_STATUS_RESPONSE";
    case MessageType::RESEND_CHAIN_REQUEST:
        return "RESEND_CHAIN";
    case MessageType::RESEND_CHAIN_RESPONSE:
        return "RESEND_CHAIN_RESPONSE";
    default:
        return "UNKNOWN";
    }
}
} // namespace zyza
#endif // ZYZZYVA_A_LIBZYZA_MESSAGEHEADER_H
