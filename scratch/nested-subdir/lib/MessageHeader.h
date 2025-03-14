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
} // namespace zyza
#endif // ZYZZYVA_A_LIBZYZA_MESSAGEHEADER_H
