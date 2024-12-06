#ifndef ZYZZYVA_A_LIBZYZA_MESSAGEHEADER_H
#define ZYZZYVA_A_LIBZYZA_MESSAGEHEADER_H
#include <cstdint>
namespace zyza {
struct MessageHeader {
  uint32_t messageSize;
  uint16_t senderIdx;
  uint16_t messageType;
};

enum class MessageType {
  MESSAGE_TYPE_REQUEST = 1,
  MESSAGE_TYPE_RESPONSE = 2,
  MESSAGE_TYPE_PROPOSAL = 3,
  MESSAGE_TYPE_ACK = 4,
  MESSAGE_TYPE_QC = 5,
  MESSAGE_TYPE_REDIRECT = 6,
};
} // namespace zyza
#endif // ZYZZYVA_A_LIBZYZA_MESSAGEHEADER_H
