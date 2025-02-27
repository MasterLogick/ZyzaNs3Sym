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

protected:
  ZyzaCommon(int nodesCount, int cancelersPerProposal,
             std::vector<std::vector<uint8_t>> &serializedPublicKeys);

  bool validateProposal(const proto::SignedMessage::Reader &proposal,
                        const uint8_t *expectedPrevProposalHash,
                        int expectedProposalSigner, int proposalIndex);

  int nodesCount;
  int quorumSize;
  int cancelersPerProposal;
  secp256k1_context *secpCtx;
  std::vector<secp256k1_pubkey> publicKeys;

  bool verifyData(const capnp::Data::Reader &data,
                  const proto::Signature::Reader &signature);

  bool verifySignedMessage(const proto::SignedMessage::Reader &signedMessage);

  bool verifyData(const uint8_t *hash, const uint8_t *sign, int signer);

  std::set<uint16_t> getProposalCancelers(const uint8_t *proposalHash);
};

} // namespace zyza

#endif // NS3_ZYZACOMMON_H
