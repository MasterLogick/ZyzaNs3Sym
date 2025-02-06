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
    // client-node communication
    REQUEST = 1,
    REDIRECT_REQUEST = 2,
    RESPONSE = 3,

    // node-leader fast path communication
    NEW_PROPOSAL = 4,
    PROPOSAL_ACK = 5,
    PROPOSAL_KEEP_REQUEST = 6,

    // node-node fallback path communication
    FALLBACK_ALERT = 7,
    PROPOSAL_STATUS_REQUEST = 8,
    PROPOSAL_STATUS_RESPONSE = 9,
    RECOVERY = 10,

    // node history recovery
    RESEND_CHAIN_REQUEST = 11,
    RESEND_CHAIN_RESPONSE = 12,
};

constexpr const char*
messageTypeToString(MessageType type)
{
    switch (type)
    {
    case MessageType::REQUEST:
        return "REQUEST";
    case MessageType::REDIRECT_REQUEST:
        return "REDIRECT_REQUEST";
    case MessageType::RESPONSE:
        return "RESPONSE";

    case MessageType::NEW_PROPOSAL:
        return "NEXT_ROUND_PROPOSAL";
    case MessageType::PROPOSAL_ACK:
        return "ROUND_ACK";
    case MessageType::PROPOSAL_KEEP_REQUEST:
        return "PROPOSAL_KEEP_REQUEST";

    case MessageType::FALLBACK_ALERT:
        return "FALLBACK_ALERT";
    case MessageType::PROPOSAL_STATUS_REQUEST:
        return "PROPOSAL_STATUS_REQUEST";
    case MessageType::PROPOSAL_STATUS_RESPONSE:
        return "PROPOSAL_STATUS_RESPONSE";
    case MessageType::RECOVERY:
        return "RECOVERY";

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
