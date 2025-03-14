#ifndef NS3_MESSAGETYPE_H
#define NS3_MESSAGETYPE_H

namespace zyza {

enum class MessageType {
  // client-node communication
  REQUEST = 1,
  REDIRECT_REQUEST = 2,
  RESPONSE = 3,
  CLIENT_RESPONSE = 4,
  REQUEST_CANCEL = 5,

  // node-leader fast path communication
  PROPOSAL = 6,
  PROPOSAL_ACK_1 = 7,
  PROPOSAL_ACK_2 = 9,

  // node-node fallback path communication
  FALLBACK_ALERT = 10,
  RECOVERY_STATE = 11,
  CLIENT_RESPONSES = 12,
  RECOVERY = 13,

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
  case MessageType::PROPOSAL_ACK_1:
    return "PROPOSAL_ACK_1";
  case MessageType::PROPOSAL_ACK_2:
    return "PROPOSAL_ACK_2";

  case MessageType::FALLBACK_ALERT:
    return "FALLBACK_ALERT";
  case MessageType::RECOVERY_STATE:
    return "RECOVERY_STATE";
  case MessageType::CLIENT_RESPONSES:
    return "CLIENT_RESPONSES";
  case MessageType::RECOVERY:
    return "RECOVERY";

  case MessageType::RESEND_CHAIN_REQUEST:
    return "RESEND_CHAIN_REQUEST";
  case MessageType::RESEND_CHAIN_RESPONSE:
    return "RESEND_CHAIN_RESPONSE";

  default:
    return "UNKNOWN";
  }
}
} // namespace zyza

#endif // NS3_MESSAGETYPE_H
