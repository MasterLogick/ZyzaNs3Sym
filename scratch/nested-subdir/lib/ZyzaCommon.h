#ifndef NS3_ZYZACOMMON_H
#define NS3_ZYZACOMMON_H

#include "capnp/message.h"
#include "lib/zyza.capnp.h"
#include "secp256k1.h"

#include <list>
#include <optional>
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

    bool validateProposal(
        const proto::Proposal::Reader& proposal,
        const uint8_t* expectedPrevProposalHash,
        int expectedProposalSigner,
        bool checkQuorumSize,
        int proposalIndex,
        bool mustContainAcks,
        std::optional<std::reference_wrapper<std::list<std::pair<uint8_t[32], capnp::MallocMessageBuilder>>>>
            pendingChain);
    int nodesCount;
    int quorumSize;
    secp256k1_context* secpCtx;
    std::vector<secp256k1_pubkey> publicKeys;
};

} // namespace zyza

#endif // NS3_ZYZACOMMON_H
