#include "ZyzaReplica.h"

#include "ns3/core-module.h"

#include <capnp/message.h>
#include <capnp/serialize.h>
#include <cassert>
#include <iostream>
#include <memory>
#include <openssl/sha.h>
#include <secp256k1.h>
#include <sys/random.h>
#include <thread>

namespace zyza
{
NS_LOG_COMPONENT_DEFINE("ZyzaReplica");

ZyzaReplica::ZyzaReplica(int nodesCount,
                         int idx,
                         ns3::PointToPointStarHelper& p2psh,
                         std::vector<std::vector<uint8_t>>& serializedPublicKeys,
                         std::span<const uint8_t> privateKey,
                         std::chrono::milliseconds fallbackTimeout)
    : Endpoint(p2psh.GetSpokeNode(idx)),
      ZyzaCommon(nodesCount, serializedPublicKeys),
      idx(idx),
      alertTimeout(fallbackTimeout),
      currentFastPathLeader(0),
      currentBackupPathLeader(0),
      initPassed(false),
      alertTimerEvent(),
      proposalOrd(0),
      p2psh(p2psh)
{
    assert(privateKey.size() == 32);
    memcpy(seckey, privateKey.data(), 32);
    assert(secp256k1_ec_seckey_verify(secpCtx, seckey));
    activeNodeConnections.resize(nodesCount);
    sendNetworkStatusRequest();
}

void
ZyzaReplica::sendToClient(const std::string& dstIp,
                          uint16_t dstPort,
                          MessageType messageType,
                          capnp::MessageBuilder& message)
{
    uint64_t msgId = 0;
    auto rc = getrandom(&msgId, sizeof(msgId), 0);
    assert(rc == sizeof(msgId));
    uint32_t size = capnp::computeSerializedSizeInWords(message) * 8 + sizeof(MessageHeader);
    auto data = std::make_unique<uint8_t[]>(size);
    new (data.get())
        MessageHeader(size, static_cast<uint16_t>(idx), static_cast<uint16_t>(messageType), msgId);
    kj::ArrayOutputStream aos({data.get() + sizeof(MessageHeader), size - sizeof(MessageHeader)});
    capnp::writeMessage(aos, message);
    ns3::Address sinkAddress(ns3::InetSocketAddress(dstIp.c_str(), dstPort));
    std::clog << ns3::Simulator::Now().As() << ": " << idx << ": sending message "
              << messageTypeToString(messageType) << " to client" << std::endl;
    serverUdpSocket->SendTo(data.get(), size, 0, sinkAddress);
}

void
ZyzaReplica::sendToNode(int node, MessageType messageType, capnp::MessageBuilder& message)
{
    NS_LOG_DEBUG(idx << " " << ns3::Simulator::Now().As(ns3::Time::S) << " sending message "
                     << messageTypeToString(messageType) << " to " << node);
    auto h = activeNodeConnections[node];
    uint32_t size = capnp::computeSerializedSizeInWords(message) * 8 + sizeof(MessageHeader);
    auto data = std::make_unique<char[]>(size);
    uint64_t msgId = 0;
    auto rc = getrandom(&msgId, sizeof(msgId), 0);
    assert(rc == sizeof(msgId));
    auto* header = new (data.get())
        MessageHeader(size, static_cast<uint16_t>(idx), static_cast<uint16_t>(messageType), msgId);
    kj::ArrayOutputStream aos({reinterpret_cast<uint8_t*>(data.get() + sizeof(MessageHeader)),
                               size - sizeof(MessageHeader)});
    capnp::writeMessage(aos, message);
    if (h != nullptr)
    {
        std::clog << ns3::Simulator::Now().As() << ": " << idx << ": sending "
                  << messageTypeToString(messageType) << " to " << node << " msgId: " << std::hex
                  << header->msgId << std::dec << std::endl;
        //        hexdump(data.get(), size);
        h->Send(reinterpret_cast<const uint8_t*>(data.get()), size, 0);
    }
    else
    {
        std::clog << ns3::Simulator::Now().As() << ": " << idx << ": adding pending message "
                  << messageTypeToString(messageType) << " to " << node << " msgId: " << std::hex
                  << header->msgId << std::dec << std::endl;
        //        hexdump(data.get(), size);
        pendingNodeMessages[node].emplace_back(std::move(data), size);
    }
}

void
ZyzaReplica::restartConnectionToNode(int i)
{
    NS_LOG_INFO(idx << " " << ns3::Simulator::Now().As(ns3::Time::S) << " restart connection to "
                    << i);
    auto con =
        ns3::Socket::CreateSocket(p2psh.GetSpokeNode(idx), ns3::TcpSocketFactory::GetTypeId());
    con->Bind();
    ns3::Address sinkAddress(ns3::InetSocketAddress(p2psh.GetSpokeIpv4Address(i), 1234));
    con->SetConnectCallback(
        [this, i](ns3::Ptr<ns3::Socket> con) {
            NS_LOG_INFO(idx << " " << ns3::Simulator::Now().As(ns3::Time::S) << " connected to "
                            << i);
            activeNodeConnections[i] = con;
            sendPendingNodeMessages(i);
        },
        [this, i](auto) -> void {
            NS_LOG_ERROR(idx << " " << ns3::Simulator::Now().As(ns3::Time::MS)
                             << " failed to connect to " << i);
        });
    if (activeNodeConnections[i] != nullptr)
    {
        activeNodeConnections[i]->Close();
        activeNodeConnections[i] = nullptr;
    }
    con->Connect(sinkAddress);
}

void
ZyzaReplica::StartApplication()
{
    Endpoint::run();
}

void
ZyzaReplica::onTcpMessage(std::span<const uint8_t> message)
{
    auto* header = reinterpret_cast<const MessageHeader*>(message.data());
    auto content = message.subspan<sizeof(MessageHeader)>();
    assert(header->messageSize == message.size());
    auto messageType = static_cast<MessageType>(header->messageType);
    if (header->senderIdx == 0xffff)
    {
        return;
    }
    std::clog << ns3::Simulator::Now().As() << ": " << idx
              << ": got message: " << messageTypeToString(messageType) << " from "
              << header->senderIdx << " msgId: " << std::hex << header->msgId << std::dec
              << std::endl;
    capnp::FlatArrayMessageReader reader(
        {reinterpret_cast<const capnp::word*>(content.data()), content.size() / 8});
    if (messageType == MessageType::NEW_PROPOSAL)
    {
        processProposal(reader.getRoot<proto::Proposal>());
    }
    else if (messageType == MessageType::PROPOSAL_ACK)
    {
        processAcknowledgement(reader.getRoot<proto::Acknowledgement>());
    }
    else if (messageType == MessageType::PROPOSAL_KEEP_REQUEST)
    {
        processProposalKeepRequest(reader.getRoot<proto::ProposalKeepRequest>());
    }
    else if (messageType == MessageType::FALLBACK_ALERT)
    {
        processFallbackAlert(reader.getRoot<proto::FallbackAlert>());
    }
    else if (messageType == MessageType::PROPOSAL_STATUS_REQUEST)
    {
        processProposalStatusRequest(reader.getRoot<proto::ProposalStatusRequest>());
    }
    else if (messageType == MessageType::PROPOSAL_STATUS_RESPONSE)
    {
        processProposalStatusResponse(reader.getRoot<proto::ProposalStatusResponse>());
    }
    else if (messageType == MessageType::RECOVERY)
    {
        processRecovery(reader.getRoot<proto::Recovery>());
    }
    else if (messageType == MessageType::RESEND_CHAIN_REQUEST)
    {
        processResendChainRequest(reader.getRoot<proto::ResendChainRequest>());
    }
    else if (messageType == MessageType::RESEND_CHAIN_RESPONSE)
    {
        processResendChainResponse(reader.getRoot<proto::ResendChainResponse>());
    }
}

void
ZyzaReplica::onUdpMessage(std::span<const uint8_t> message)
{
    auto* header = reinterpret_cast<const MessageHeader*>(message.data());
    auto content = message.subspan<sizeof(MessageHeader)>();
    assert(header->messageSize == message.size());
    auto messageType = static_cast<MessageType>(header->messageType);
    if (header->senderIdx != 0xffff)
    {
        return;
    }
    std::clog << ns3::Simulator::Now().As() << ": " << idx
              << ": got message: " << messageTypeToString(messageType) << " from "
              << header->senderIdx << " msgId: " << std::hex << header->msgId << std::dec
              << std::endl;
    capnp::FlatArrayMessageReader reader(
        {reinterpret_cast<const capnp::word*>(content.data()), content.size() / 8});
    if (messageType == MessageType::REQUEST)
    {
        processRequest(reader.getRoot<proto::Request>());
    }
}

void
ZyzaReplica::processRequest(const proto::Request::Reader& request)
{
    if (currentState == ReplicaState::LEADER_FAST)
    {
        pendingRequests.emplace_back(new capnp::MallocMessageBuilder())->setRoot(request);
    }
    else
    {
        capnp::MallocMessageBuilder redirectBuilder;
        auto redirect = redirectBuilder.initRoot<proto::Redirect>();
        redirect.setRedirect(currentFastPathLeader);
        sendToClient(request.getRespAddr(),
                     request.getRespPort(),
                     MessageType::REDIRECT_REQUEST,
                     redirectBuilder);
    }
}

void
ZyzaReplica::processProposal(const proto::Proposal::Reader& proposal)
{
    if (currentState != ReplicaState::BACKUP_FAST)
    {
        return;
    }
    if (!validateProposal(proposal,
                          pendingChain.back().first,
                          initPassed ? currentFastPathLeader : 0,
                          initPassed,
                          proposalOrd,
                          maxPendingChainLength == pendingChain.size(),
                          pendingChain))
    {
        return;
    }
    capnp::FlatArrayMessageReader bodyMessage(
        {reinterpret_cast<const capnp::word*>(proposal.getBody().begin()),
         proposal.getBody().size() / 8});
    auto body = bodyMessage.getRoot<proto::ProposalBody>();
    std::clog << idx << ": got valid proposal with ord " << body.getOrd() << std::endl;
    if (initPassed)
    {
        for (const auto& item : body.getAcknowledgements())
        {
            auto& d = acceptedChain.emplace_back();
            auto& s = pendingChain.front();
            memcpy(d.first, s.first, 32);
            d.second.setRoot(s.second.getRoot<proto::Proposal>().asReader());
            pendingChain.pop_front();
        }
    }
    uint8_t newProposalHash[32];
    SHA256(proposal.getBody().asBytes().begin(),
           proposal.getBody().asBytes().size(),
           newProposalHash);
    //  hexdump(proposalHash, "received proposal body hash");
    {
        auto& pendingBlock = pendingChain.emplace_back();
        memcpy(pendingBlock.first, newProposalHash, 32);
        pendingBlock.second.setRoot(proposal);
    }
    for (const auto& item : body.getRequests())
    {
        responseToClient(item, newProposalHash);
    }
    secp256k1_ecdsa_signature groupSig;
    int rc = secp256k1_ecdsa_sign(secpCtx, &groupSig, newProposalHash, seckey, nullptr, nullptr);
    assert(rc == 1);
    uint8_t compressedSig[64];
    rc = secp256k1_ecdsa_signature_serialize_compact(secpCtx, compressedSig, &groupSig);
    assert(rc == 1);
    capnp::MallocMessageBuilder ackBuilder;
    auto ack = ackBuilder.initRoot<proto::Acknowledgement>();
    ack.setProposalHash({newProposalHash, 32});
    ack.getSign().setSign({compressedSig, 64});
    ack.getSign().setIdx(idx);
    sendToNode(currentFastPathLeader, MessageType::PROPOSAL_ACK, ackBuilder);
    alertTimerEvent.Cancel();
    alertTimerEvent = ns3::Simulator::Schedule(ns3::Time::From(alertTimeout.count(), ns3::Time::MS),
                                               [this] { switchToFallback(); });
    initPassed = true;
    proposalOrd++;
    std::clog << "processed proposal" << std::endl;
}

void
ZyzaReplica::processAcknowledgement(const proto::Acknowledgement::Reader& reader)
{
    if (currentState != ReplicaState::LEADER_FAST)
    {
        return;
    }
    if (reader.getProposalHash().size() != 32)
    {
        std::clog << "wrong ack proposal hash size" << std::endl;
        return;
    }
    if (reader.getSign().getSign().size() != 64)
    {
        std::clog << "wrong ack proposal sign size" << std::endl;
        return;
    }
    for (auto& item : pendingProposalAcks)
    {
        if (memcmp(item.first, reader.getProposalHash().begin(), 32) != 0)
        {
            continue;
        }
        if (item.second.contains(reader.getSign().getIdx()))
        {
            std::clog << "ack resend" << std::endl;
            return;
        }
        secp256k1_ecdsa_signature sig;
        int rc = secp256k1_ecdsa_signature_parse_compact(secpCtx,
                                                         &sig,
                                                         reader.getSign().getSign().begin());
        if (!rc)
        {
            std::clog << "wrong ack proposal sign pack sign" << std::endl;
            return;
        }
        rc = secp256k1_ecdsa_verify(secpCtx,
                                    &sig,
                                    item.first,
                                    &publicKeys[reader.getSign().getIdx()]);
        if (!rc)
        {
            std::clog << "wrong ack proposal sign" << std::endl;
            return;
        }
        auto* d = item.second[reader.getSign().getIdx()];
        memcpy(d, reader.getSign().getSign().begin(), 64);
        if (pendingProposalAcks.size() == quorumSize)
        {
            startNewRound();
        }
        std::clog << "processed ack" << std::endl;
        return;
    }
    hexdump(reader.getProposalHash().begin(), "unknown ack proposal hash");
}

void
ZyzaReplica::processFallbackAlert(const proto::FallbackAlert::Reader& fallbackAlert)
{
    assert(!sentDropRequests);
    capnp::FlatArrayMessageReader unackedProposalBodyReader(
        {reinterpret_cast<const capnp::word*>(fallbackAlert.getUnackedProposal().begin()),
         fallbackAlert.getUnackedProposal().size() / 8});
    auto proposal = unackedProposalBodyReader.getRoot<proto::Proposal>();
    auto myUnackedProposal = lastUnackedProposal.getRoot<proto::Proposal>();
    capnp::FlatArrayMessageReader myUnackedProposalBodyReader(
        {reinterpret_cast<const capnp::word*>(myUnackedProposal.getBody().begin()),
         myUnackedProposal.getBody().size() / 8});
    auto myUnackedProposalBody = myUnackedProposalBodyReader.getRoot<proto::ProposalBody>();
    if (!validateProposal(proposal,
                          myUnackedProposalBody.getPrevProposalHash().begin(),
                          myUnackedProposal.getSign().getIdx(),
                          true,
                          -1))
    {
        return;
    }
    uint8_t hash[32];
    SHA256(fallbackAlert.getUnackedProposal().begin(),
           fallbackAlert.getUnackedProposal().size(),
           hash);
    secp256k1_ecdsa_signature sig;
    int rc = secp256k1_ecdsa_signature_parse_compact(secpCtx,
                                                     &sig,
                                                     fallbackAlert.getSign().getSign().begin());
    if (!rc)
    {
        std::clog << "wrong fallback alert packed sign" << std::endl;
        return;
    }
    rc = secp256k1_ecdsa_verify(secpCtx, &sig, hash, &publicKeys[fallbackAlert.getSign().getIdx()]);
    if (!rc)
    {
        std::clog << "wrong fallback alert sign" << std::endl;
        return;
    }
    std::unique_ptr<capnp::MallocMessageBuilder> mb(new capnp::MallocMessageBuilder());
    mb->setRoot(fallbackAlert);
    acceptedFallbackAlerts[fallbackAlert.getSign().getIdx()] = std::move(mb);
    std::clog << "accepted fallback alert" << std::endl;
    if (acceptedFallbackAlerts.size() == quorumSize)
    {
        std::clog << "approved force switching to fallback" << std::endl;
        sendDropRequests();
    }
}

void
ZyzaReplica::sendDropRequests()
{
    fallbackClientResponsesCollected = 0;
    for (const auto& item : acceptedFallbackAlerts)
    {
        auto alert = item.second->getRoot<proto::FallbackAlert>();
        capnp::FlatArrayMessageReader alertProposalReader(
            {reinterpret_cast<const capnp::word*>(alert.getUnackedProposal().begin()),
             alert.getUnackedProposal().size() / 8});
        auto proposal = alertProposalReader.getRoot<proto::Proposal>();
        capnp::FlatArrayMessageReader proposalBodyReader(
            {reinterpret_cast<const capnp::word*>(proposal.getBody().begin()),
             proposal.getBody().size() / 8});
        auto proposalBody = proposalBodyReader.getRoot<proto::ProposalBody>();
        for (const auto& request : proposalBody.getRequests())
        {
            auto reqId = request.getId();
            if (uniqueRequests.contains(reqId))
            {
                continue;
            }
            auto& state = uniqueRequests[reqId];
            state.request.setRoot(request);
            if (collectedQuorumCertificates.contains(reqId))
            {
                auto d = collectedQuorumCertificates[reqId].getRoot<proto::QuorumCertificate>();
                state.response.setRoot(d.asReader());
                state.hasResponse = true;
                state.responseIsDrop = false;
                fallbackClientResponsesCollected++;
            }
            else
            {
                state.hasResponse = false;
            }
        }
    }
    std::clog << "got " << uniqueRequests.size() << " unique requests" << std::endl;
    for (auto& item : uniqueRequests)
    {
        if (item.second.hasResponse)
        {
            continue;
        }
        std::shared_ptr<capnp::MallocMessageBuilder> quorumDropRequestBuilder(
            new capnp::MallocMessageBuilder());
        auto quorumDropRequest = quorumDropRequestBuilder->initRoot<proto::QuorumDropRequest>();
        auto request = item.second.request.getRoot<proto::Request>();
        quorumDropRequest.setReqId(request.getId());
        auto proof = quorumDropRequest.initProof(quorumSize);
        int i = 0;
        for (const auto& acceptedFallbackAlert : acceptedFallbackAlerts)
        {
            auto fa = acceptedFallbackAlert.second->getRoot<proto::FallbackAlert>();
            proof.setWithCaveats(i, fa);
            i++;
        }
        sendToClient(request.getRespAddr().cStr(),
                     request.getRespPort(),
                     MessageType::QUORUM_DROP_REQUEST,
                     quorumDropRequestBuilder);
    }
    sentDropRequests = true;
    if (fallbackClientResponsesCollected == uniqueRequests.size())
    {
        broadcastRecovery();
    }
}

void
ZyzaReplica::startNewRound()
{
    std::clog << "starting a new round" << std::endl;
    auto t = ns3::Simulator::Now();
    if (sumCount == 0)
    {
        start = ns3::Simulator::Now();
    }
    sumCount++;
    std::clog << "t: " << (t - last).As(ns3::Time::S) << std::endl;
    std::clog << "avg(" << sumCount << "): " << ((t - start) / sumCount).As(ns3::Time::S)
              << std::endl;
    std::clog << "sent: " << sentStatistics << std::endl;
    std::clog << "sent pkt size: " << sentMsgSize << std::endl;
    std::clog << "recv: " << recvStatistics << std::endl;
    std::clog << "recv pkt size: " << recvMsgSize << std::endl;
    sentStatistics = 0;
    recvStatistics = 0;
    last = t;
    auto& newBlock = acceptedChain.emplace_back();
    memcpy(newBlock.first, proposalHash, 32);
    newBlock.second.setRoot(pendingProposal->getRoot<proto::Proposal>().asReader());
    initPassed = true;
    capnp::MallocMessageBuilder proposalBodyBuilder;
    auto proposalBody = proposalBodyBuilder.initRoot<proto::ProposalBody>();
    proposalBody.initRequests(pendingRequests.size());
    for (int i = 0; i < pendingRequests.size(); ++i)
    {
        proposalBody.getRequests().setWithCaveats(i, pendingRequests[i]->getRoot<proto::Request>());
    }
    proposalBody.setPrevProposalHash({proposalHash, 32});
    proposalBody.setOrd(proposalOrd);
    proposalOrd++;
    auto acks = proposalBody.initAcknowledgements(pendingProposalAcks.size());
    auto iter = pendingProposalAcks.begin();
    for (int i = 0; i < pendingProposalAcks.size(); ++i)
    {
        acks[i].setIdx(iter->first);
        acks[i].setSign({reinterpret_cast<const kj::byte*>(iter->second), 64});
        iter++;
    }
    auto proposalBodySerialized = capnp::messageToFlatArray(proposalBodyBuilder);
    SHA256(proposalBodySerialized.asBytes().begin(),
           proposalBodySerialized.asBytes().size(),
           proposalHash);
    hexdump(proposalHash, "new round proposal body hash");

    for (const auto& pendingRequest : pendingRequests)
    {
        responseToClient(pendingRequest->getRoot<proto::Request>());
    }
    pendingRequests.clear();

    secp256k1_ecdsa_signature sig;
    int rc = secp256k1_ecdsa_sign(secpCtx, &sig, proposalHash, seckey, nullptr, nullptr);
    assert(rc == 1);
    uint8_t compSig[64];
    rc = secp256k1_ecdsa_signature_serialize_compact(secpCtx, compSig, &sig);
    assert(rc == 1);
    pendingProposal = std::make_unique<capnp::MallocMessageBuilder>();
    auto proposal = pendingProposal->initRoot<proto::Proposal>();
    proposal.setBody(
        {proposalBodySerialized.asBytes().begin(), proposalBodySerialized.asBytes().size()});
    auto sign = proposal.initSign();
    sign.setSign({compSig, 64});
    sign.setIdx(idx);

    for (int i = 0; i < nodesCount; ++i)
    {
        if (i == idx)
        {
            continue;
        }
        sendToNode(i, MessageType::NEW_PROPOSAL, *pendingProposal);
    }

    pendingProposalAcks.clear();
    rc = secp256k1_ecdsa_sign(secpCtx, &sig, proposalHash, seckey, nullptr, nullptr);
    assert(rc == 1);
    rc = secp256k1_ecdsa_signature_serialize_compact(secpCtx, compSig, &sig);
    assert(rc == 1);
    memcpy(pendingProposalAcks[idx], compSig, 64);
    collectedQuorumCertificates.clear();
    std::clog << "started a new round" << std::endl;
}

std::vector<uint8_t>
ZyzaReplica::processRequest(std::span<const uint8_t> request)
{
    std::vector<uint8_t> resp(request.size() * 2);
    memcpy(resp.data(), request.data(), request.size());
    memcpy(resp.data() + request.size(), request.data(), request.size());
    return std::move(resp);
}

void
ZyzaReplica::onListeningStart()
{
    for (int i = 0; i < nodesCount; ++i)
    {
        restartConnectionToNode(i);
    }
}

void
ZyzaReplica::sendPendingNodeMessages(int i)
{
    auto h = activeNodeConnections[i];
    if (pendingNodeMessages.contains(i))
    {
        for (auto& item : pendingNodeMessages[i])
        {
            auto* header = reinterpret_cast<const MessageHeader*>(item.first.get());
            std::clog << ns3::Simulator::Now().As() << ": " << idx << ": sending pending message "
                      << messageTypeToString(static_cast<MessageType>(header->messageType))
                      << " to " << i << " msgId: " << std::hex << header->msgId << std::dec
                      << std::endl;
            h->Send(reinterpret_cast<const uint8_t*>(item.first.get()), item.second, 0);
        }
        pendingNodeMessages.erase(i);
    }
}

void
ZyzaReplica::responseToClient(const proto::Request::Reader& request, uint8_t* proposalHash)
{
    capnp::MallocMessageBuilder respBodyBuilder;
    auto respBody = respBodyBuilder.initRoot<proto::ResponseBody>();
    respBody.setId(request.getId());
    auto respImpl = processRequest(request.getImpl());
    respBody.setImpl({respImpl.data(), respImpl.size()});
    respBody.setProposalHash({proposalHash, 32});
    auto respBodySerial = capnp::messageToFlatArray(respBodyBuilder);
    auto respBuilder = std::make_shared<capnp::MallocMessageBuilder>();
    auto resp = respBuilder->initRoot<proto::Response>();
    resp.setBody(respBodySerial.asBytes());
    uint8_t hash[32];
    SHA256(respBodySerial.asBytes().begin(), respBodySerial.asBytes().size(), hash);
    hexdump(hash, "resp body hash");
    secp256k1_ecdsa_signature sig;
    int rc = secp256k1_ecdsa_sign(secpCtx, &sig, hash, seckey, nullptr, nullptr);
    assert(rc == 1);
    uint8_t sigPack[64];
    rc = secp256k1_ecdsa_signature_serialize_compact(secpCtx, sigPack, &sig);
    assert(rc == 1);
    resp.getSign().setIdx(idx);
    resp.getSign().setSign({sigPack, 64});
    sendToClient(request.getRespAddr().cStr(),
                 request.getRespPort(),
                 MessageType::RESPONSE,
                 respBuilder);
}

void
ZyzaReplica::switchToFallback()
{
    std::clog << idx << ": switching to fallback" << std::endl;
    alertTimerEvent.Cancel();
    isInFallbackState = true;
    sentDropRequests = false;
    currentBackupPathLeader = (currentFastPathLeader + 1) % nodesCount;
    capnp::MallocMessageBuilder fallbackAlertBuilder;
    auto fallbackAlert = fallbackAlertBuilder.initRoot<proto::FallbackAlert>();
    auto flatUnackedProposal = capnp::messageToFlatArray(lastUnackedProposal);
    fallbackAlert.setUnackedProposal(flatUnackedProposal.asBytes());
    uint8_t sign[64];
    signData(flatUnackedProposal.asBytes().begin(), flatUnackedProposal.asBytes().size(), sign);
    fallbackAlert.getSign().setSign({sign, 64});
    fallbackAlert.getSign().setIdx(idx);
    sendToNode(currentBackupPathLeader, MessageType::FALLBACK_ALERT, fallbackAlertBuilder);
}

bool
ZyzaReplica::signData(const uint8_t* data, size_t size, uint8_t* result)
{
    uint8_t hash[32];
    SHA256(data, size, hash);
    return signData(hash, result);
}

bool
ZyzaReplica::signData(const uint8_t* hash, uint8_t* result)
{
    secp256k1_ecdsa_signature sig;
    int rc = secp256k1_ecdsa_sign(secpCtx, &sig, hash, seckey, nullptr, nullptr);
    if (rc != 1)
    {
        return false;
    }
    rc = secp256k1_ecdsa_signature_serialize_compact(secpCtx, result, &sig);
    return rc == 1;
}

void
ZyzaReplica::processQuorumDropResponse(const proto::QuorumDropResponse::Reader& quorumDropResponse)
{
    assert(sentDropRequests);
    auto reqId = quorumDropResponse.getReqId();
    if (!uniqueRequests.contains(reqId))
    {
        std::clog << "wrong quorum drop response req id" << std::endl;
        return;
    }
    if (quorumDropResponse.getDropSecret().size() != 32)
    {
        std::clog << "wrong quorum drop response secret size" << std::endl;
        return;
    }
    auto& frs = uniqueRequests[reqId];
    uint8_t hash[32];
    SHA256(quorumDropResponse.getDropSecret().begin(), 32, hash);
    auto* expectedHash = frs.request.getRoot<proto::Request>().getDropHash().begin();
    if (memcmp(hash, expectedHash, 32) != 0)
    {
        hexdump(hash, "wrong drop secret hash");
        hexdump(expectedHash, "expected secret hash");
        return;
    }
    if (frs.hasResponse)
    {
        std::clog << "has fallback response already" << std::endl;
        return;
    }
    frs.hasResponse = true;
    frs.responseIsDrop = true;
    frs.response.setRoot(quorumDropResponse);
    fallbackClientResponsesCollected++;
    if (fallbackClientResponsesCollected == uniqueRequests.size())
    {
        broadcastRecovery();
    }
}

void
ZyzaReplica::broadcastRecovery()
{
    assert(fallbackClientResponsesCollected == uniqueRequests.size());
    assert(acceptedFallbackAlerts.size() == quorumSize);
    assert(sentDropRequests);
    std::clog << "broadcasting recovery message" << std::endl;
    capnp::MallocMessageBuilder recoveryBuilder;
    auto recovery = recoveryBuilder.initRoot<proto::Recovery>();
    {
        auto proof = recovery.initProof(quorumSize);
        int i = 0;
        for (const auto& item : acceptedFallbackAlerts)
        {
            proof.setWithCaveats(i, item.second->getRoot<proto::FallbackAlert>());
            i++;
        }
    }
    bool hasQC = false;
    for (auto& item : uniqueRequests)
    {
        if (!item.second.responseIsDrop)
        {
            recovery.setQuorumCertificate(item.second.response.getRoot<proto::QuorumCertificate>());
            hasQC = true;
            break;
        }
    }
    if (!hasQC)
    {
        auto clientResponses = recovery.initClientResponses(uniqueRequests.size());
        int i = 0;
        for (auto& item : uniqueRequests)
        {
            auto response = clientResponses[i];
            response.setReqId(item.first);
            assert(item.second.hasResponse);
            response.setDropSecret(
                item.second.response.getRoot<proto::QuorumDropResponse>().getDropSecret());
        }
    }
    for (int i = 0; i < nodesCount; ++i)
    {
        sendToNode(i, MessageType::RECOVERY, recoveryBuilder);
    }
}

void
ZyzaReplica::processRecovery(const proto::Recovery::Reader& recovery)
{
    assert(initPassed);
    uint16_t expectedLeader = 0;
    uint8_t expectedHash[32];
    {
        auto proposal = lastUnackedProposal.getRoot<proto::Proposal>();
        expectedLeader = proposal.getSign().getIdx();
        capnp::FlatArrayMessageReader reader(
            {reinterpret_cast<const capnp::word*>(proposal.getBody().asBytes().begin()),
             proposal.getBody().asBytes().size() / 8});
        memcpy(expectedHash,
               reader.getRoot<proto::ProposalBody>().getPrevProposalHash().begin(),
               32);
    }
    if (recovery.getProof().size() != quorumSize)
    {
        std::clog << "wrong proof size" << std::endl;
        return;
    }
    std::map<uint64_t, std::pair<bool, capnp::MallocMessageBuilder>> requestStatus;
    std::vector<uint8_t[32]> proposalHashes(recovery.getProof().size());
    auto proposalHashesIter = proposalHashes.begin();
    for (const auto& item : recovery.getProof())
    {
        capnp::FlatArrayMessageReader reader(
            {reinterpret_cast<const capnp::word*>(item.getUnackedProposal().asBytes().begin()),
             item.getUnackedProposal().asBytes().size() / 8});
        auto proposal = reader.getRoot<proto::Proposal>();
        if (!validateProposal(proposal, expectedHash, expectedLeader, true, proposalOrd))
        {
            std::clog << "wrong recovery proof proposal" << std::endl;
            return;
        }
        if (!validateData(item.getUnackedProposal(), item.getSign()))
        {
            std::clog << "wrong recovery proof sign" << std::endl;
            return;
        }
        capnp::FlatArrayMessageReader bodyReader(
            {reinterpret_cast<const capnp::word*>(proposal.getBody().asBytes().begin()),
             proposal.getBody().asBytes().size() / 8});
        for (const auto& req : bodyReader.getRoot<proto::ProposalBody>().getRequests())
        {
            auto reqId = req.getId();
            if (requestStatus.contains(reqId))
            {
                continue;
            }
            requestStatus[reqId].first = false;
            requestStatus[reqId].second.setRoot(req);
        }
        SHA256(proposal.getBody().asBytes().begin(),
               proposal.getBody().asBytes().size(),
               *proposalHashesIter);
        proposalHashesIter++;
    }
    int proposalForQc = -1;
    switch (recovery.which())
    {
    case proto::Recovery::CLIENT_RESPONSES: {
        for (const auto& cr : recovery.getClientResponses())
        {
            uint64_t reqId = cr.getReqId();
            if (requestStatus[reqId].first)
            {
                std::clog << "duplicate client response" << std::endl;
                return;
            }
            auto& reqPair = requestStatus[reqId];
            auto request = reqPair.second.getRoot<proto::Request>();
            if (cr.getDropSecret().size() != 32)
            {
                std::clog << "wrong drop secret size" << std::endl;
                return;
            }
            uint8_t dropSecretHash[32];
            SHA256(cr.getDropSecret().begin(), 32, dropSecretHash);
            if (memcmp(dropSecretHash, request.getDropHash().begin(), 32) != 0)
            {
                std::clog << "wrong drop secret value" << std::endl;
                return;
            }
            reqPair.first = true;
        }
        break;
    }
    case proto::Recovery::QUORUM_CERTIFICATE: {
        auto qc = recovery.getQuorumCertificate();
        uint64_t reqId = qc.getResponse().getId();
        if (requestStatus[reqId].first)
        {
            std::clog << "duplicate client response" << std::endl;
            return;
        }
        auto& reqPair = requestStatus[reqId];
        if (!validateQuorumCertificate(qc, nullptr))
        {
            std::clog << "wrong quorum certificate" << std::endl;
            return;
        }
        reqPair.first = true;
        for (int i = 0; i < proposalHashes.size(); ++i)
        {
            if (memcmp(proposalHashes[i], qc.getResponse().getProposalHash().begin(), 32) == 0)
            {
                proposalForQc = i;
            }
        }
        break;
    }
    }
    if (proposalForQc == -1)
    {
        proposalForQc = 0;
    }
    auto acceptedProposalData = recovery.getProof()[proposalForQc].getUnackedProposal().asBytes();
    capnp::FlatArrayMessageReader proposalReader(
        {reinterpret_cast<const capnp::word*>(acceptedProposalData.begin()),
         acceptedProposalData.size() / 8});
    recoverWithProposal(proposalReader.getRoot<proto::Proposal>());
}

bool
ZyzaReplica::validateData(const capnp::Data::Reader& data,
                          const proto::Signature::Reader& signature)
{
    uint8_t hash[32];
    SHA256(data.begin(), data.size(), hash);
    if (signature.getSign().size() != 64)
    {
        std::clog << "wrong signature size" << std::endl;
        return false;
    }
    return validateData(hash, signature.getSign().begin(), signature.getIdx());
}

bool
ZyzaReplica::validateData(const uint8_t* hash, const uint8_t* sign, int signer)
{
    secp256k1_ecdsa_signature sig;
    int rc = secp256k1_ecdsa_signature_parse_compact(secpCtx, &sig, sign);
    if (!rc)
    {
        std::clog << "wrong pack sign" << std::endl;
        return false;
    }
    rc = secp256k1_ecdsa_verify(secpCtx, &sig, hash, &publicKeys[signer]);
    if (!rc)
    {
        std::clog << "wrong ack proposal sign" << std::endl;
        return false;
    }
    return true;
}

bool
ZyzaReplica::validateQuorumCertificate(const proto::QuorumCertificate::Reader& qc,
                                       uint8_t* expectedResponseProposalHash)
{
    if (qc.getResponse().getProposalHash().size() != 32)
    {
        std::clog << "wrong quorum cert proposal hash size" << std::endl;
        return false;
    }
    if (expectedResponseProposalHash != nullptr)
    {
        if (memcmp(qc.getResponse().getProposalHash().begin(), expectedResponseProposalHash, 32) !=
            0)
        {
            hexdump(qc.getResponse().getProposalHash().begin(), "wrong quorum cert proposal hash");
            hexdump(expectedResponseProposalHash, "expected hash");
            return false;
        }
    }
    if (qc.getSigns().size() != quorumSize)
    {
        std::clog << "wrong quorum size" << std::endl;
        return false;
    }
    capnp::MallocMessageBuilder respBodyBuilder;
    respBodyBuilder.setRoot(qc.getResponse());
    auto data = capnp::messageToFlatArray(respBodyBuilder);
    uint8_t hash[32];
    SHA256(data.asBytes().begin(), data.asBytes().size(), hash);
    hexdump(hash, "quorum resp body hash");
    for (const auto& item : qc.getSigns())
    {
        if (item.getSign().size() != 64)
        {
            std::clog << "wrong quorum sign size" << std::endl;
            return false;
        }
        secp256k1_ecdsa_signature sig;
        int rc = secp256k1_ecdsa_signature_parse_compact(secpCtx, &sig, item.getSign().begin());
        if (rc != 1)
        {
            std::clog << "wrong quorum compressed sign" << std::endl;
            return false;
        }
        rc = secp256k1_ecdsa_verify(secpCtx, &sig, hash, &publicKeys[item.getIdx()]);
        if (rc != 1)
        {
            std::clog << "wrong quorum sign" << std::endl;
            return false;
        }
    }
    return true;
}

void
ZyzaReplica::recoverWithProposal(const proto::Proposal::Reader& proposal)
{
    isInFallbackState = false;
    pendingProposalAcks.clear();
    collectedQuorumCertificates.clear();
    isInFallbackState = false;
    sentDropRequests = false;
    acceptedFallbackAlerts.clear();
    uniqueRequests.clear();
    fallbackClientResponsesCollected = 0;
    SHA256(proposal.getBody().begin(), proposal.getBody().size(), proposalHash);
    capnp::FlatArrayMessageReader bodyReader(
        {reinterpret_cast<const capnp::word*>(proposal.getBody().begin()),
         proposal.getBody().size() / 8});
    auto proposalBody = bodyReader.getRoot<proto::ProposalBody>();
    for (const auto& item : proposalBody.getRequests())
    {
        responseToClient(item);
    }
    if (!isLeader())
    {
        uint8_t sign[64];
        signData(proposalHash, sign);
        capnp::MallocMessageBuilder ackBuilder;
        auto ack = ackBuilder.initRoot<proto::Acknowledgement>();
        ack.setProposalHash({proposalHash, 32});
        ack.getSign().setSign({sign, 64});
        ack.getSign().setIdx(idx);
        sendToNode(currentBackupPathLeader, MessageType::PROPOSAL_ACK, ackBuilder);
        alertTimerEvent.Cancel();
        alertTimerEvent =
            ns3::Simulator::Schedule(ns3::Time::From(alertTimeout.count(), ns3::Time::MS),
                                     [this] { switchToFallback(); });
    }
    else
    {
        signData(proposalHash, pendingProposalAcks[idx]);
    }
    currentFastPathLeader = currentBackupPathLeader;
    std::clog << "recovered with new leader: " << currentFastPathLeader << std::endl;
    hexdump(proposalHash, "selected proposal");
}

void
ZyzaReplica::processNetworkStatusRequest(const proto::NetworkStatusRequest::Reader& nsr)
{
    if (nsr.getIdx() >= nodesCount)
    {
        std::clog << "wrong network status request node idx" << std::endl;
        return;
    }
    capnp::MallocMessageBuilder resp;
    resp.initRoot<proto::NetworkStatusResponse>().setCurrentLeader(currentFastPathLeader);
    sendToNode(nsr.getIdx(), MessageType::NETWORK_STATUS_RESPONSE, resp);
}

void
ZyzaReplica::processNetworkStatusResponse(const proto::NetworkStatusResponse::Reader& nsr)
{
    if (!sentNetworkStatusRequest)
    {
        std::clog << "unknown network status response" << std::endl;
        return;
    }
    if (isLeader() && !initPassed && nsr.getCurrentLeader() == currentFastPathLeader)
    {
        sentNetworkStatusRequest = false;
        startLeaderZeroNode();
    }
    else
    {
        if (nsr.getCurrentLeader() == idx)
        {
            std::clog << "wrong network status response" << std::endl;
            return;
        }
        sentNetworkStatusRequest = false;
        capnp::MallocMessageBuilder resendChainBuilder;
        auto resendChain = resendChainBuilder.initRoot<proto::ResendChainRequest>();
        if (acceptedChain.empty())
        {
            uint8_t zeroHash[32];
            memset(zeroHash, 0, 32);
            resendChain.setLastAckedProposal({zeroHash, 32});
        }
        else
        {
            auto& hash = acceptedChain.back().first;
            resendChain.setLastAckedProposal({hash, 32});
        }
        resendChain.setIdx(idx);
        sendToNode(nsr.getCurrentLeader(), MessageType::RESEND_CHAIN_REQUEST, resendChainBuilder);
        sentResendChainRequest = true;
    }
}

void
ZyzaReplica::startLeaderZeroNode()
{
    capnp::MallocMessageBuilder bodyBuilder;
    auto body = bodyBuilder.initRoot<proto::ProposalBody>();
    body.initRequests(0);
    body.setPrevProposalHash({proposalHash, 32});
    body.initAcknowledgements(0);
    body.setOrd(proposalOrd);
    proposalOrd++;
    auto serializedBody = capnp::messageToFlatArray(bodyBuilder);
    SHA256(serializedBody.asBytes().begin(), serializedBody.asBytes().size(), proposalHash);
    hexdump(proposalHash, "first proposal body hash");
    secp256k1_ecdsa_signature sig;
    int rc = secp256k1_ecdsa_sign(secpCtx, &sig, proposalHash, seckey, nullptr, nullptr);
    assert(rc == 1);
    uint8_t sigSerial[64];
    rc = secp256k1_ecdsa_signature_serialize_compact(secpCtx, sigSerial, &sig);
    assert(rc == 1);
    pendingProposal = std::make_unique<capnp::MallocMessageBuilder>();
    auto proposal = pendingProposal->initRoot<proto::Proposal>();
    proposal.setBody(serializedBody.asBytes());
    proposal.getSign().setIdx(idx);
    proposal.getSign().setSign({sigSerial, 64});
    rc = secp256k1_ecdsa_sign(secpCtx, &sig, proposalHash, seckey, nullptr, nullptr);
    assert(rc == 1);
    rc = secp256k1_ecdsa_signature_serialize_compact(secpCtx, sigSerial, &sig);
    assert(rc == 1);
    memcpy(pendingProposalAcks[idx], sigSerial, 64);
    for (int i = 0; i < nodesCount; ++i)
    {
        if (i == idx)
            continue;
        sendToNode(i, MessageType::NEW_PROPOSAL, *pendingProposal);
    }
}

void
ZyzaReplica::processResendChainRequest(const proto::ResendChainRequest::Reader& nsr)
{
    if (!isLeader())
    {
        return;
    }
    if (nsr.getLastAckedProposal().size() != 32)
    {
        std::clog << "wrong resend chain proposal hash size" << std::endl;
        return;
    }
    if (nsr.getIdx() >= nodesCount)
    {
        std::clog << "wrong resend chain node idx" << std::endl;
        return;
    }
    if (acceptedChain.empty())
    {
        return;
    }
    uint8_t zeroHash[32];
    memset(zeroHash, 0, 32);
    if (memcmp(zeroHash, nsr.getLastAckedProposal().begin(), 32) == 0)
    {
        resendChainPart(acceptedChain.begin(), nsr.getIdx(), acceptedChain.size());
    }
    else
    {
        auto iter = acceptedChain.end();
        int count = 0;
        while (iter != acceptedChain.begin())
        {
            iter--;
            count++;
            if (memcmp(iter->first, nsr.getLastAckedProposal().begin(), 32) == 0)
            {
                iter++;
                resendChainPart(iter, nsr.getIdx(), count);
                break;
            }
        }
    }
}

void
ZyzaReplica::resendChainPart(
    std::list<std::pair<uint8_t[32], capnp::MallocMessageBuilder>>::iterator it,
    int node,
    int partSize)
{
    capnp::MallocMessageBuilder resendChainResponseBuilder;
    auto resendChainResponse = resendChainResponseBuilder.initRoot<proto::ResendChainResponse>();
    auto chainPart = resendChainResponse.initChainPart(partSize + 1);
    int i = 0;
    while (it != acceptedChain.end())
    {
        if (i == partSize)
        {
            // todo fix
            return;
        }
        chainPart.setWithCaveats(i, it->second.getRoot<proto::Proposal>());
        i++;
        it++;
    }
    std::clog << "i == partSize: " << i << " " << partSize << std::endl;
    if (i < partSize)
    {
        return;
    }
    assert(i == partSize);

    chainPart.setWithCaveats(partSize, pendingProposal->getRoot<proto::Proposal>());
    sendToNode(node, MessageType::RESEND_CHAIN_RESPONSE, resendChainResponseBuilder);
}

void
ZyzaReplica::processResendChainResponse(const proto::ResendChainResponse::Reader& nsr)
{
    if (!sentResendChainRequest)
    {
        return;
    }
    sentResendChainRequest = false;
    auto chainPart = nsr.getChainPart();
    if (chainPart.size() == 0)
    {
        return;
    }
    if (acceptedChain.empty() && chainPart.size() == 1)
    {
        return;
    }
    auto it = chainPart.begin();
    uint8_t zeroHash[32];
    memset(zeroHash, 0, 32);
    bool oldInitPassed = initPassed;
    while (it != chainPart.end())
    {
        const uint8_t* expectedPrevHash = initPassed ? acceptedChain.back().first : zeroHash;
        if (!validateProposal(*it, expectedPrevHash, -1, initPassed, -1))
        {
            break;
        }
        auto& newBlock = acceptedChain.emplace_back();
        SHA256(it->getBody().begin(), it->getBody().size(), newBlock.first);
        newBlock.second.setRoot(*it);
        initPassed = true;
        currentFastPathLeader = it->getSign().getIdx();
        it++;
    }
    if (it == chainPart.begin())
    {
        return;
    }
    auto& lastBlock = acceptedChain.back();
    pendingProposal->setRoot(lastBlock.second.getRoot<proto::Proposal>().asReader());
    memcpy(proposalHash, lastBlock.first, 32);
    acceptedChain.pop_back();
    if (initPassed)
    {
        alertTimerEvent.Cancel();
        alertTimerEvent =
            ns3::Simulator::Schedule(ns3::Time::From(alertTimeout.count(), ns3::Time::MS),
                                     [this] { switchToFallback(); });
    }
}
} // namespace zyza
