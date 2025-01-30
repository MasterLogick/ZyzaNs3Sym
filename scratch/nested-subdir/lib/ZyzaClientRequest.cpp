#include "ZyzaClientRequest.h"

#include "../../src/internet/model/tcp-socket-factory.h"
#include "capnp/message.h"
#include "capnp/serialize.h"
#include "lib/zyza.capnp.h"

#include "ns3/core-module.h"

#include <cassert>
#include <cstring>
#include <iostream>
#include <map>
#include <openssl/sha.h>
#include <sys/random.h>
#include <uvw.hpp>
#include <uvw/tcp.h>

namespace zyza
{
ZyzaClientRequest::ZyzaClientRequest(uint16_t leaderHint,
                                     int clientId,
                                     int nodesCount,
                                     std::vector<std::vector<uint8_t>>& serializedPublicKeys,
                                     ns3::PointToPointStarHelper& p2psh,
                                     std::chrono::milliseconds requestTimeout)
    : Endpoint(p2psh.GetSpokeNode(nodesCount + clientId)),
      ZyzaCommon(nodesCount, serializedPublicKeys),
      p2psh(p2psh),
      requestTimeout(requestTimeout),
      clientId(clientId)
{
    uint8_t addr[4];
    p2psh.GetSpokeIpv4Address(nodesCount + clientId).Serialize(addr);
    host = std::to_string(addr[0]) + "." + std::to_string(addr[1]) + "." + std::to_string(addr[2]) +
           "." + std::to_string(addr[3]);
    ssize_t rc = getrandom(&reqId, 8, 0);
    assert(rc == 8);
    rc = getrandom(dropSecret, 32, 0);
    assert(rc == 32);
    if (leaderHint < nodesCount)
    {
        currentLeader = leaderHint;
    }
    else
    {
        currentLeader = 0xffff;
    }
}

void
ZyzaClientRequest::onListeningStart()
{
    requestTimeoutTimerEvent =
        ns3::Simulator::Schedule(ns3::Time::From(requestTimeout.count(), ns3::Time::MS), [this] {
            auto rc = getrandom(&currentLeader, sizeof(currentLeader), 0);
            assert(rc == 2);
            currentLeader %= nodesCount;
            sendRequestToNode(currentLeader);
        });
    if (currentLeader == 0xffff)
    {
        auto rc = getrandom(&currentLeader, sizeof(currentLeader), 0);
        assert(rc == 2);
        currentLeader %= nodesCount;
    }
    sendRequestToNode(currentLeader);
}

void
ZyzaClientRequest::sendRequestToNode(uint16_t i)
{
    auto requestBuilder = std::make_shared<capnp::MallocMessageBuilder>();
    auto request = requestBuilder->initRoot<proto::Request>();
    request.setId(reqId);
    request.setRespAddr(host);
    request.setRespPort(1235);
    request.setImpl({req.data(), req.size()});
    uint8_t dropHash[32];
    SHA256(dropSecret, 32, dropHash);
    request.setDropHash({dropHash, 32});
    std::clog << ns3::Simulator::Now().As() << ": " << clientId << ": sending request to " << i
              << std::endl;
    sendToNode(i, MessageType::REQUEST, requestBuilder);
}

void
ZyzaClientRequest::onTcpMessage(std::span<const uint8_t> message)
{
    // client is not expected to receive tcp messages
}

void
ZyzaClientRequest::onUdpMessage(std::span<const uint8_t> message)
{
    auto* header = reinterpret_cast<const MessageHeader*>(message.data());
    std::clog << ns3::Simulator::Now().As() << ": " << clientId << ": client got message: "
              << messageTypeToString(static_cast<MessageType>(header->messageType)) << " from "
              << header->senderIdx << ": " << std::hex << header->msgId << std::dec << std::endl;
    auto content = message.subspan<sizeof(MessageHeader)>();
    assert(header->messageSize == message.size());
    capnp::FlatArrayMessageReader responseReader(
        {reinterpret_cast<const capnp::word*>(content.data()), content.size() / 8});
    if (static_cast<MessageType>(header->messageType) == MessageType::RESPONSE)
    {
        processResponse(responseReader.getRoot<proto::Response>());
    }
    else if (static_cast<MessageType>(header->messageType) == MessageType::REDIRECT_REQUEST)
    {
        processRedirect(responseReader.getRoot<proto::Redirect>());
    }
    else if (static_cast<MessageType>(header->messageType) == MessageType::QUORUM_DROP_REQUEST)
    {
        processQuorumDropRequest(responseReader.getRoot<proto::QuorumDropRequest>(),
                                 header->senderIdx);
    }
}

void
ZyzaClientRequest::run(std::span<const uint8_t> request,
                       std::function<void(std::vector<uint8_t>)> responseCallback)
{
    this->responseCallback = responseCallback;
    req = request;
    Endpoint::run();
}

void
ZyzaClientRequest::sendToNode(int node,
                              MessageType messageType,
                              std::shared_ptr<capnp::MessageBuilder> message)
{
    uint64_t msgId = 0;
    auto rc = getrandom(&msgId, sizeof(msgId), 0);
    assert(rc == sizeof(msgId));
    uint32_t size = capnp::computeSerializedSizeInWords(*message) * 8 + sizeof(MessageHeader);
    auto data = std::make_unique<uint8_t[]>(size);
    new (data.get()) MessageHeader(size,
                                   static_cast<uint16_t>(0xffff),
                                   static_cast<uint16_t>(messageType),
                                   msgId);
    kj::ArrayOutputStream aos({data.get() + sizeof(MessageHeader), size - sizeof(MessageHeader)});
    capnp::writeMessage(aos, *message);
    ns3::Address address(ns3::InetSocketAddress(p2psh.GetSpokeIpv4Address(node), 1235));
    std::clog << ns3::Simulator::Now().As() << ": " << clientId << ": sending "
              << messageTypeToString(static_cast<MessageType>(messageType)) << " to " << node
              << ": " << std::hex << msgId << std::dec << std::endl;
    serverUdpSocket->SendTo(data.get(), size, 0, address);
}

void
ZyzaClientRequest::processResponse(const proto::Response::Reader& response)
{
    capnp::FlatArrayMessageReader responseBodyBuilder(
        {reinterpret_cast<const capnp::word*>(response.getBody().begin()),
         response.getBody().size() / 8});
    auto responseBody = responseBodyBuilder.getRoot<proto::ResponseBody>();
    if (responseBody.getId() != reqId)
    {
        std::clog << "wrong request id" << std::endl;
        return;
    }
    if (response.getSign().getSign().size() != 64)
    {
        std::clog << "wrong response sign size" << std::endl;
        return;
    }
    if (responseBody.getProposalHash().size() != 32)
    {
        std::clog << "wrong proposal hash size: " << responseBody.getProposalHash().size()
                  << std::endl;
        return;
    }
    capnp::MallocMessageBuilder b;
    auto respBodyClone = b.initRoot<proto::ResponseBody>();
    b.setRoot(responseBody);
    auto data = capnp::messageToFlatArray(b);
    uint8_t hash[32];
    SHA256(response.getBody().begin(), response.getBody().size(), hash);
    hexdump(hash, "response body hash");
    secp256k1_ecdsa_signature sig;
    int rc = secp256k1_ecdsa_signature_parse_compact(secpCtx,
                                                     &sig,
                                                     response.getSign().getSign().begin());
    if (rc != 1)
    {
        std::clog << "wrong response packed sign" << std::endl;
        return;
    }
    rc = secp256k1_ecdsa_verify(secpCtx, &sig, hash, &publicKeys[response.getSign().getIdx()]);
    if (rc != 1)
    {
        std::clog << "wrong response sign" << std::endl;
        return;
    }
    memcpy(pendingQc[response.getSign().getIdx()].first, response.getSign().getSign().begin(), 64);
    memcpy(pendingQc[response.getSign().getIdx()].second, hash, 32);
    int c = 0;
    for (const auto& item : pendingQc)
    {
        if (memcmp(item.second.second, hash, 32) == 0)
        {
            c++;
        }
    }
    if (c == quorumSize)
    {
        auto qcBuilder = std::make_shared<capnp::MallocMessageBuilder>();
        auto qc = qcBuilder->initRoot<proto::QuorumCertificate>();
        qc.setResponse(responseBody);
        auto signs = qc.initSigns(quorumSize);
        int i = 0;
        for (const auto& item : pendingQc)
        {
            if (memcmp(item.second.second, hash, 32) == 0)
            {
                signs[i].setIdx(item.first);
                signs[i].setSign({item.second.first, 64});
                i++;
            }
        }
        //        loop->walk([](auto& handle) { handle.close(); });

        requestTimeoutTimerEvent.Cancel();
        for (int j = 0; j < nodesCount; ++j)
        {
            sendToNode(j, MessageType::ACCEPT_QUORUM_CERTIFICATE, qcBuilder);
        }
        resp.assign(responseBody.getImpl().begin(), responseBody.getImpl().end());
        responseCallback(resp);
    }
}

void
ZyzaClientRequest::processRedirect(const proto::Redirect::Reader& redirect)
{
    currentLeader = redirect.getRedirect() % nodesCount;
    std::clog << clientId << ": redirecting request to " << currentLeader << std::endl;
    sendRequestToNode(currentLeader);
}

void
ZyzaClientRequest::processQuorumDropRequest(const proto::QuorumDropRequest::Reader& qdr, int sender)
{
    if (qdr.getReqId() != reqId)
    {
        std::clog << "wrong req id" << std::endl;
    }
    auto proof = qdr.getProof();
    if (qdr.getProof().size() != quorumSize)
    {
        std::clog << "wrong proof size" << std::endl;
        return;
    }
    uint8_t expectedPrevProposalHash[32];
    uint16_t expectedPrevProposalSigner = 0;
    {
        capnp::FlatArrayMessageReader proposalReader(
            {reinterpret_cast<const capnp::word*>(proof[0].getUnackedProposal().begin()),
             proof[0].getUnackedProposal().size() / 8});
        auto proposal = proposalReader.getRoot<proto::Proposal>();
        capnp::FlatArrayMessageReader proposalBodyReader(
            {reinterpret_cast<const capnp::word*>(proposal.getBody().begin()),
             proposal.getBody().size() / 8});
        auto proposalBody = proposalBodyReader.getRoot<proto::ProposalBody>();
        if (proposalBody.getPrevProposalHash().size() != 32)
        {
            std::clog << "wrong proposal's prev proposal hash size: "
                      << proposalBody.getPrevProposalHash().size() << std::endl;
            return;
        }
        memcpy(expectedPrevProposalHash, proposalBody.getPrevProposalHash().begin(), 32);
        expectedPrevProposalSigner = proposal.getSign().getIdx();
    }
    hexdump(expectedPrevProposalHash, "expected prev proposal hash");
    std::clog << "expected proposal leader: " << expectedPrevProposalSigner << std::endl;
    for (const auto& item : proof)
    {
        capnp::FlatArrayMessageReader unackedProposalReader(
            {reinterpret_cast<const capnp::word*>(item.getUnackedProposal().begin()),
             item.getUnackedProposal().size() / 8});
        auto unackedProposal = unackedProposalReader.getRoot<proto::Proposal>();
        if (!validateProposal(unackedProposal,
                              expectedPrevProposalHash,
                              expectedPrevProposalSigner,
                              true,
                              -1))
        {
            std::clog << "failed to verify drop proof" << std::endl;
            return;
        }
    }
    std::shared_ptr<capnp::MallocMessageBuilder> responseBuilder(new capnp::MallocMessageBuilder());
    auto response = responseBuilder->initRoot<proto::QuorumDropResponse>();
    response.setReqId(reqId);
    response.setDropSecret({dropSecret, 32});
    sendToNode(sender, MessageType::QUORUM_DROP_RESPONSE, responseBuilder);
    std::clog << "sent drop responses" << std::endl;
}
} // namespace zyza
