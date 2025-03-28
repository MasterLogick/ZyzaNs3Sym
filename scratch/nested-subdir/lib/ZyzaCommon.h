#ifndef NS3_ZYZACOMMON_H
#define NS3_ZYZACOMMON_H

#include "capnp/message.h"
#include "lib/zyza.capnp.h"
#include "secp256k1.h"

#include <list>
#include <optional>
#include <set>
#include <span>
#include <vector>

namespace zyza {
class ZyzaCommon {
public:
  static void hexdump(const uint8_t arr[64], const char *note);

  static void hexdump(const void *arr, size_t size);

  static void hexdump(const capnp::AnyPointer::Reader &message,
                      const char *note);

  static void hexdump(const capnp::AnyStruct::Reader &message,
                      const char *note);

  static void hashStruct(const capnp::AnyPointer::Reader &data,
                         std::span<uint8_t, 32> hash32);

  static void hashStruct(const capnp::AnyStruct::Reader &data,
                         std::span<uint8_t, 32> hash32);

  static void fillRandom(void *data, size_t size);

protected:
  ZyzaCommon(int nodesCount,
             std::vector<std::vector<uint8_t>> &serializedPublicKeys);

  bool verifyData(const capnp::AnyPointer::Reader &data,
                  const proto::Signature::Reader &signature);

  bool verifySignedMessage(
      const proto::SignedMessage<capnp::AnyPointer>::Reader &signedMessage);

  bool verifyData(const uint8_t *hash, const uint8_t *sign, int signer);

  int nodesCount;
  int quorumSize;
  std::vector<secp256k1_pubkey> publicKeys;
};

} // namespace zyza

#endif // NS3_ZYZACOMMON_H
