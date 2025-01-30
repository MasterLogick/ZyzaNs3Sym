#include "ZyzaCommon.h"

#include <capnp/serialize.h>
#include <cassert>
#include <iostream>
#include <openssl/sha.h>
#include <sstream>
#include <sys/random.h>

namespace zyza
{

ZyzaCommon::ZyzaCommon(int nodesCount, std::vector<std::vector<uint8_t>>& serializedPublicKeys)
    : nodesCount(nodesCount),
      quorumSize(nodesCount - nodesCount / 3),
      publicKeys(nodesCount)
{
    secpCtx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    uint8_t seed[32];
    ssize_t res = getrandom(seed, 32, 0);
    assert(res == 32);
    assert(secp256k1_context_randomize(secpCtx, seed));
    for (size_t i = 0; i < publicKeys.size(); i++)
    {
        auto rc = secp256k1_ec_pubkey_parse(secpCtx,
                                            &publicKeys[i],
                                            serializedPublicKeys[i].data(),
                                            serializedPublicKeys[i].size());
        assert(rc);
    }
}

bool
ZyzaCommon::validateProposal(const proto::Proposal::Reader& proposal,
                             const uint8_t* expectedPrevProposalHash,
                             int expectedProposalSigner,
                             bool checkQuorumSize,
                             int proposalIndex)
{
    capnp::FlatArrayMessageReader bodyMessage(
        {reinterpret_cast<const capnp::word*>(proposal.getBody().begin()),
         proposal.getBody().size() / 8});
    auto body = bodyMessage.getRoot<proto::ProposalBody>();
    if (proposalIndex != -1 && body.getOrd() != proposalIndex)
    {
        std::clog << "wrong proposal index " << body.getOrd() << ", expected " << proposalIndex
                  << std::endl;
        return false;
    }
    if (body.getAcknowledgements().size() != quorumSize && checkQuorumSize)
    {
        std::clog << "wrong proposal quorum size" << std::endl;
        return false;
    }
    if (proposal.getSign().getSign().size() != 64)
    {
        std::clog << "wrong proposal sign size" << std::endl;
        return false;
    }
    if (expectedProposalSigner != -1)
    {
        if (proposal.getSign().getIdx() != expectedProposalSigner)
        {
            std::clog << "wrong proposal signer" << std::endl;
            return false;
        }
    }
    if (body.getPrevProposalHash().size() != 32)
    {
        std::clog << "wrong proposal hash size" << std::endl;
        return false;
    }
    if (expectedPrevProposalHash != nullptr)
    {
        if (memcmp(expectedPrevProposalHash, body.getPrevProposalHash().begin(), 32) != 0)
        {
            hexdump(body.getPrevProposalHash().begin(), "wrong proposal hash");
            hexdump(expectedPrevProposalHash, "expected hash");
            return false;
        }
    }
    int rc = 0;
    for (const auto& item : body.getAcknowledgements())
    {
        if (item.getSign().size() != 64)
        {
            std::clog << "wrong proposal ack sign size" << std::endl;
            return false;
        }
        if (item.getIdx() >= nodesCount)
        {
            std::clog << "wrong proposal ack node id" << std::endl;
            return false;
        }
        secp256k1_ecdsa_signature sig;
        rc = secp256k1_ecdsa_signature_parse_compact(secpCtx, &sig, item.getSign().begin());
        if (!rc)
        {
            std::clog << "wrong proposal ack packed sign" << std::endl;
            return false;
        }
        rc = secp256k1_ecdsa_verify(secpCtx,
                                    &sig,
                                    body.getPrevProposalHash().begin(),
                                    &publicKeys[item.getIdx()]);
        if (!rc)
        {
            std::clog << "wrong proposal ack sign" << std::endl;
            return false;
        }
    }
    for (const auto& item : body.getRequests())
    {
        if (item.getDropHash().size() != 32)
        {
            std::clog << "wrong request's drop hash" << std::endl;
            return false;
        }
    }
    uint8_t receivedProposalHash[32];
    SHA256(proposal.getBody().asBytes().begin(),
           proposal.getBody().asBytes().size(),
           receivedProposalHash);
    hexdump(receivedProposalHash, "received proposal body hash");
    secp256k1_ecdsa_signature sig;
    rc = secp256k1_ecdsa_signature_parse_compact(secpCtx,
                                                 &sig,
                                                 proposal.getSign().getSign().begin());
    if (!rc)
    {
        std::clog << "wrong proposal packed sign" << std::endl;
        return false;
    }
    if (expectedProposalSigner != -1)
    {
        rc = secp256k1_ecdsa_verify(secpCtx,
                                    &sig,
                                    receivedProposalHash,
                                    &publicKeys[expectedProposalSigner]);
        if (!rc)
        {
            std::clog << "wrong proposal sign" << std::endl;
            return false;
        }
    }
    return true;
}

void
ZyzaCommon::hexdump(const uint8_t* arr, const char* note)
{
    std::stringstream ss;
    for (int i = 0; i < 32; ++i)
    {
        ss << std::hex << (int)arr[i];
    }
    std::clog << note << ": " << ss.str() << std::endl;
}

void
ZyzaCommon::hexdump(const void* arr, size_t size)
{
    const auto* ptr = reinterpret_cast<const uint8_t*>(arr);
    std::clog << std::hex;
    for (size_t i = 0; i < size; ++i)
    {
        std::clog << (int)ptr[i];
    }
    std::clog << std::dec << std::endl;
}
} // namespace zyza