#ifndef NS3_ZYZACOMMON_H
#define NS3_ZYZACOMMON_H

#include "lib/zyza.capnp.h"
#include "secp256k1.h"

#include <vector>

namespace zyza
{
class ZyzaCommon
{
  public:
    static void hexdump(const uint8_t arr[64], const char* note);

    static void hexdump(const void* arr, size_t size);
  protected:
    ZyzaCommon(int nodesCount, std::vector<std::vector<uint8_t>>& serializedPublicKeys);

    bool validateProposal(const proto::Proposal::Reader& proposal,
                          const uint8_t* expectedPrevProposalHash,
                          int expectedProposalSigner,
                          bool checkQuorumSize,
                          int proposalIndex);
    int nodesCount;
    int quorumSize;
    secp256k1_context* secpCtx;
    std::vector<secp256k1_pubkey> publicKeys;
};

} // namespace zyza

#endif // NS3_ZYZACOMMON_H
