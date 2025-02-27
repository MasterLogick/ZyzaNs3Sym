#ifndef ZYZZYVA_A_LIBZYZA_MESSAGEHEADER_H
#define ZYZZYVA_A_LIBZYZA_MESSAGEHEADER_H
#include <cstdint>

namespace zyza {
struct MessageHeader {
  uint32_t messageSize;
  uint16_t senderIdx;
  uint16_t messageType;
  uint64_t msgId;
};

enum class MessageType {
  // client-node communication
  REQUEST = 1,
  REDIRECT_REQUEST = 2,
  RESPONSE = 3,
  CLIENT_RESPONSE = 4,
  REQUEST_CANCEL = 5,

  // node-leader fast path communication
  PROPOSAL = 6,
  PROPOSAL_ACK = 7,

  // node-node fallback path communication
  FALLBACK_ALERT = 9,
  RECOVERY = 10,
  RECOVERY_ACK = 11,

  // proposal cancel on clients
  PROPOSAL_CANCEL_REQUEST = 12,
  PROPOSAL_CANCEL_RESPONSE = 13,

  // node history recovery
  RESEND_CHAIN_REQUEST = 14,
  RESEND_CHAIN_RESPONSE = 15,
};

constexpr const char *messageTypeToString(MessageType type) {
  switch (type) {
  case MessageType::REQUEST:
    return "REQUEST";
  case MessageType::REDIRECT_REQUEST:
    return "REDIRECT_REQUEST";
  case MessageType::RESPONSE:
    return "RESPONSE";
  case MessageType::CLIENT_RESPONSE:
    return "CLIENT_RESPONSE";
  case MessageType::REQUEST_CANCEL:
    return "REQUEST_CANCEL";

  case MessageType::PROPOSAL:
    return "PROPOSAL";
  case MessageType::PROPOSAL_ACK:
    return "PROPOSAL_ACK";

  case MessageType::FALLBACK_ALERT:
    return "FALLBACK_ALERT";
  case MessageType::RECOVERY:
    return "RECOVERY";
  case MessageType::RECOVERY_ACK:
    return "RECOVERY_ACK";

  case MessageType::PROPOSAL_CANCEL_REQUEST:
    return "PROPOSAL_CANCEL_REQUEST";
  case MessageType::PROPOSAL_CANCEL_RESPONSE:
    return "PROPOSAL_CANCEL_RESPONSE";

  case MessageType::RESEND_CHAIN_REQUEST:
    return "RESEND_CHAIN_REQUEST";
  case MessageType::RESEND_CHAIN_RESPONSE:
    return "RESEND_CHAIN_RESPONSE";

  default:
    return "UNKNOWN";
  }
}
} // namespace zyza
#endif // ZYZZYVA_A_LIBZYZA_MESSAGEHEADER_H
