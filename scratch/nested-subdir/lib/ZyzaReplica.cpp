#include "ZyzaReplica.h"

#include "../../../src/point-to-point-layout/model/point-to-point-star.h"

#include "ns3/core-module.h"

#include <capnp/message.h>
#include <capnp/serialize.h>
#include <cassert>
#include <iomanip>
#include <iostream>
#include <memory>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <secp256k1.h>
#include <sys/random.h>
#include <thread>

namespace zyza
{
NS_LOG_COMPONENT_DEFINE("ZyzaReplica");

void
hexdump(kj::Array<capnp::word>& arr)
{
    std::stringstream ss;
    for (int i = 0; i < arr.size(); ++i)
    {
        ss << std::hex << *reinterpret_cast<uint64_t*>(arr.begin() + i) << std::endl;
    }
    std::cout << ss.str() << std::endl;
}

void
hexdump(const uint8_t arr[64], const char* note)
{
    //  std::stringstream ss;
    //  for (int i = 0; i < 32; ++i) {
    //    ss << std::hex << (int)arr[i];
    //  }
    //  std::cout << note << ": " << ss.str() << std::endl;
}

ZyzaReplica::ZyzaReplica(
    int nodesCount,
    int idx,
    //                         int port,
    //                         ns3::NodeContainer& nodes,
    //                         std::vector<std::vector<ns3::Ipv4InterfaceContainer>>& interfaces,
    ns3::PointToPointStarHelper& p2psh,
    std::vector<std::vector<uint8_t>>& serializedPublicKeys,
    std::span<const uint8_t> privateKey)
    : Endpoint(p2psh.GetSpokeNode(idx)),
      nodesCount(nodesCount),
      quorumSize((nodesCount + 2) / 3 + 1),
      idx(idx),
      currentLeader(0),
      publicKeys(serializedPublicKeys.size()),
      //      nodeList(nodeList),
      initPassed(false),
      //      nodes(nodes),
      //      interfaces(interfaces)
      p2psh(p2psh)
{
    assert(privateKey.size() == 32);
    assert(publicKeys.size() == nodesCount);
    //    assert(nodeList.size() == nodesCount);
    memcpy(seckey, privateKey.data(), 32);
    secpCtx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    uint8_t seed[32];
    ssize_t res = getrandom(seed, 32, 0);
    assert(res == 32);
    assert(secp256k1_context_randomize(secpCtx, seed));
    assert(secp256k1_ec_seckey_verify(secpCtx, seckey));
    for (size_t i = 0; i < publicKeys.size(); i++)
    {
        auto rc = secp256k1_ec_pubkey_parse(secpCtx,
                                            &publicKeys[i],
                                            serializedPublicKeys[i].data(),
                                            serializedPublicKeys[i].size());
        assert(rc);
    }
    memset(groupHash, 0, sizeof(groupHash));
    memset(proposalHash, 0, sizeof(proposalHash));
    if (isLeader())
    {
        capnp::MallocMessageBuilder bodyBuilder;
        auto body = bodyBuilder.initRoot<proto::ProposalBody>();
        body.initRequests(0);
        body.setPrevGroupHash({groupHash, 32});
        body.initAcknowledgements(0);
        auto serializedBody = capnp::messageToFlatArray(bodyBuilder);
        //    uint8_t hash[32];
        SHA256(proposalHash, 32, groupHash);
        SHA256(serializedBody.asBytes().begin(), serializedBody.asBytes().size(), proposalHash);
        hexdump(proposalHash, "first proposal body hash");
        hexdump(groupHash, "first group hash");
        secp256k1_ecdsa_signature sig;
        int rc = secp256k1_ecdsa_sign(secpCtx, &sig, proposalHash, seckey, nullptr, nullptr);
        assert(rc == 1);
        uint8_t sigSerial[64];
        rc = secp256k1_ecdsa_signature_serialize_compact(secpCtx, sigSerial, &sig);
        assert(rc == 1);
        auto proposal = initialProposal.initRoot<proto::Proposal>();
        proposal.setBody(serializedBody.asBytes());
        proposal.getSign().setIdx(idx);
        proposal.getSign().setSign({sigSerial, 64});
        rc = secp256k1_ecdsa_sign(secpCtx, &sig, groupHash, seckey, nullptr, nullptr);
        assert(rc == 1);
        rc = secp256k1_ecdsa_signature_serialize_compact(secpCtx, sigSerial, &sig);
        assert(rc == 1);
        char* d = pendingProposalAcks[idx];
        memcpy(d, sigSerial, 64);
    }
}

void
ZyzaReplica::processRequest(std::unique_ptr<capnp::MallocMessageBuilder> reader)
{
    if (isLeader())
    {
        pendingRequests.push_back(std::move(reader));
    }
    else
    {
        auto request = reader->getRoot<proto::Request>();
        auto redirectBuilder = std::make_shared<capnp::MallocMessageBuilder>();
        auto redirect = redirectBuilder->initRoot<proto::Redirect>();
        redirect.setRedirect(currentLeader);
        sendToClient(request.getRespAddr().asReader(),
                     request.getRespPort(),
                     MessageType::MESSAGE_TYPE_REDIRECT,
                     std::move(redirectBuilder));
    }
}

void
ZyzaReplica::processProposal(proto::Proposal::Reader reader)
{
    assert(!isLeader());
    capnp::FlatArrayMessageReader bodyMessage(
        {reinterpret_cast<const capnp::word*>(reader.getBody().begin()),
         reader.getBody().size() / 8});
    auto body = bodyMessage.getRoot<proto::ProposalBody>();
    if (body.getAcknowledgements().size() != quorumSize && initPassed)
    {
        std::cout << "wrong proposal quorum size" << std::endl;
        return;
    }
    initPassed = true;
    if (reader.getSign().getSign().size() != 64)
    {
        std::cout << "wrong proposal sign size" << std::endl;
        return;
    }
    if (reader.getSign().getIdx() != currentLeader)
    {
        std::cout << "wrong proposal leader" << std::endl;
        return;
    }
    if (body.getPrevGroupHash().size() != 32)
    {
        std::cout << "wrong proposal group response size" << std::endl;
        return;
    }
    if (memcmp(groupHash, body.getPrevGroupHash().begin(), 32) != 0)
    {
        hexdump(groupHash, "failed to compare prev group hashes");
        hexdump(body.getPrevGroupHash().begin(), "failed hash");
        return;
    }
    int rc = 0;
    for (const auto& item : body.getAcknowledgements())
    {
        if (item.getSign().size() != 64)
        {
            std::cout << "wrong proposal ack sign size" << std::endl;
            return;
        }
        if (item.getIdx() >= nodesCount)
        {
            std::cout << "wrong proposal ack node id" << std::endl;
            return;
        }
        secp256k1_ecdsa_signature sig;
        rc = secp256k1_ecdsa_signature_parse_compact(secpCtx, &sig, item.getSign().begin());
        if (!rc)
        {
            std::cout << "wrong proposal ack packed sign" << std::endl;
            return;
        }
        rc = secp256k1_ecdsa_verify(secpCtx, &sig, groupHash, &publicKeys[item.getIdx()]);
        if (!rc)
        {
            std::cout << "wrong proposal ack sign" << std::endl;
            return;
        }
    }
    uint8_t receivedProposalHash[32];
    {
        SHA256(reader.getBody().asBytes().begin(),
               reader.getBody().asBytes().size(),
               receivedProposalHash);
        hexdump(receivedProposalHash, "received proposal body hash");
        secp256k1_ecdsa_signature sig;
        rc = secp256k1_ecdsa_signature_parse_compact(secpCtx,
                                                     &sig,
                                                     reader.getSign().getSign().begin());
        if (!rc)
        {
            std::cout << "wrong proposal packed sign" << std::endl;
            return;
        }
        rc =
            secp256k1_ecdsa_verify(secpCtx, &sig, receivedProposalHash, &publicKeys[currentLeader]);
        if (!rc)
        {
            std::cout << "wrong proposal sign" << std::endl;
            return;
        }
    }

    std::unique_ptr<EVP_MD_CTX, void (*)(EVP_MD_CTX*)> evpMdCtx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    rc = EVP_DigestInit_ex2(evpMdCtx.get(), EVP_sha256(), nullptr);
    assert(rc == 1);
    rc = EVP_DigestUpdate(evpMdCtx.get(), proposalHash, 32);
    assert(rc == 1);
    hexdump(proposalHash, "prev proposal hash");
    memcpy(proposalHash, receivedProposalHash, 32);
    for (const auto& item : body.getRequests())
    {
        auto reqImpl = item.getImpl();
        capnp::MallocMessageBuilder respBodyBuilder;
        auto respBody = respBodyBuilder.initRoot<proto::ResponseBody>();
        auto respImpl = processRequest({reqImpl.begin(), reqImpl.size()});
        respBody.setImpl({respImpl.data(), respImpl.size()});
        respBody.setProposalHash({receivedProposalHash, 32});
        respBody.setId(item.getId());
        requiredQcReqId = item.getId();
        auto data = capnp::messageToFlatArray(respBodyBuilder);
        uint8_t hash[32];
        SHA256(data.asBytes().begin(), data.asBytes().size(), hash);
        hexdump(hash, "response body hash on backup");
        rc = EVP_DigestUpdate(evpMdCtx.get(), data.asBytes().begin(), data.asBytes().size());
        assert(rc == 1);
        secp256k1_ecdsa_signature sig;
        rc = secp256k1_ecdsa_sign(secpCtx, &sig, hash, seckey, nullptr, nullptr);
        assert(rc);
        uint8_t compSig[64];
        rc = secp256k1_ecdsa_signature_serialize_compact(secpCtx, compSig, &sig);
        assert(rc);
        auto respBuilder = std::make_shared<capnp::MallocMessageBuilder>();
        auto resp = respBuilder->initRoot<proto::Response>();
        resp.setBody({data.asBytes().begin(), data.asBytes().size()});
        auto signBuilder = resp.getSign();
        signBuilder.setIdx(idx);
        signBuilder.setSign({compSig, 64});
        sendToClient(item.getRespAddr(),
                     item.getRespPort(),
                     MessageType::MESSAGE_TYPE_RESPONSE,
                     respBuilder);
    }
    uint chSize = 0;
    rc = EVP_DigestFinal_ex(evpMdCtx.get(), groupHash, &chSize);
    hexdump(groupHash, "calculated group hash");
    assert(rc == 1);
    secp256k1_ecdsa_signature groupSig;
    rc = secp256k1_ecdsa_sign(secpCtx, &groupSig, groupHash, seckey, nullptr, nullptr);
    assert(rc == 1);
    uint8_t compressedSig[64];
    rc = secp256k1_ecdsa_signature_serialize_compact(secpCtx, compressedSig, &groupSig);
    assert(rc == 1);
    capnp::MallocMessageBuilder ackBuilder;
    auto ack = ackBuilder.initRoot<proto::Acknowledgement>();
    ack.setGroupHash({groupHash, 32});
    ack.getGroupSign().setSign({compressedSig, 64});
    ack.getGroupSign().setIdx(idx);
    sendToNode(currentLeader, MessageType::MESSAGE_TYPE_ACK, ackBuilder);
}

void
ZyzaReplica::processAcknowledgement(proto::Acknowledgement::Reader reader)
{
    assert(isLeader());
    if (reader.getGroupHash().size() != 32)
    {
        std::cout << "wrong ack group hash size" << std::endl;
        return;
    }
    if (reader.getGroupSign().getSign().size() != 64)
    {
        std::cout << "wrong ack group sign size" << std::endl;
        return;
    }
    if (pendingProposalAcks.contains(reader.getGroupSign().getIdx()))
    {
        std::cout << "ack resend" << std::endl;
        return;
    }
    if (memcmp(groupHash, reader.getGroupHash().begin(), 32) != 0 && initPassed)
    {
        hexdump(groupHash, "failed to compare group hashes");
        hexdump(reader.getGroupHash().begin(), "failed hash");
        return;
    }
    {
        secp256k1_ecdsa_signature sig;
        int rc = secp256k1_ecdsa_signature_parse_compact(secpCtx,
                                                         &sig,
                                                         reader.getGroupSign().getSign().begin());
        if (!rc)
        {
            std::cout << "wrong ack group sign pack sign" << std::endl;
            return;
        }
        rc = secp256k1_ecdsa_verify(secpCtx,
                                    &sig,
                                    groupHash,
                                    &publicKeys[reader.getGroupSign().getIdx()]);
        if (!rc)
        {
            std::cout << "wrong ack group sign" << std::endl;
            return;
        }
    }
    auto* d = pendingProposalAcks[reader.getGroupSign().getIdx()];
    memcpy(d, reader.getGroupSign().getSign().begin(), 64);
    if (pendingProposalAcks.size() == quorumSize)
    {
        startNewRound();
    }
}

void
ZyzaReplica::startNewRound()
{
    auto t = ns3::Simulator::Now();
    //    std::chrono::system_clock::time_point t = std::chrono::system_clock::now();
    //    std::chrono::system_clock::duration du = t - last;
    if (sumCount == 0)
    {
        start = ns3::Simulator::Now();
    }
    sumCount++;
    std::clog << "t: " << (t - last).As(ns3::Time::S) << std::endl;
    std::clog << "avg(" << sumCount << "): " << ((t - start) / sumCount).As(ns3::Time::S)
              << std::endl;
    //    NS_LOG_INFO("t: " << (t - last).As(ns3::Time::S));
    //    NS_LOG_INFO("avg(" << sumCount << "): " << ((t - start) / sumCount).As(ns3::Time::S));
    last = t;
    initPassed = true;
    std::unique_ptr<EVP_MD_CTX, void (*)(EVP_MD_CTX*)> evpMdCtx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    int rc = EVP_DigestInit_ex2(evpMdCtx.get(), EVP_sha256(), nullptr);
    assert(rc == 1);
    rc = EVP_DigestUpdate(evpMdCtx.get(), proposalHash, 32);
    assert(rc == 1);
    capnp::MallocMessageBuilder proposalBodyBuilder;
    auto proposalBody = proposalBodyBuilder.initRoot<proto::ProposalBody>();
    proposalBody.initRequests(pendingRequests.size());
    for (int i = 0; i < pendingRequests.size(); ++i)
    {
        auto req = pendingRequests[i]->getRoot<proto::Request>();
        auto respBuilder = std::make_shared<capnp::MallocMessageBuilder>();
        auto resp = respBuilder->initRoot<proto::Response>();
        capnp::MallocMessageBuilder respBodyBuilder;
        auto respBody = respBodyBuilder.initRoot<proto::ResponseBody>();
        respBody.setId(req.getId());
        auto respImpl = processRequest(req.getImpl());
        respBody.setImpl({respImpl.data(), respImpl.size()});
        auto respBodySerial = capnp::messageToFlatArray(respBodyBuilder);
        resp.setBody(respBodySerial.asBytes());
        uint8_t hash[32];
        SHA256(respBodySerial.asBytes().begin(), respBodySerial.asBytes().size(), hash);
        hexdump(hash, "response body hash on leader");
        secp256k1_ecdsa_signature sig;
        rc = secp256k1_ecdsa_sign(secpCtx, &sig, hash, seckey, nullptr, nullptr);
        assert(rc == 1);
        uint8_t sigPack[64];
        rc = secp256k1_ecdsa_signature_serialize_compact(secpCtx, sigPack, &sig);
        assert(rc == 1);
        resp.getSign().setIdx(idx);
        resp.getSign().setSign({sigPack, 64});
        sendToClient(req.getRespAddr().asString(),
                     req.getRespPort(),
                     MessageType::MESSAGE_TYPE_RESPONSE,
                     respBuilder);
        rc = EVP_DigestUpdate(evpMdCtx.get(), hash, 32);
        assert(rc == 1);
        proposalBody.getRequests().setWithCaveats(i, req);
    }
    uint chSize = 0;
    proposalBody.setPrevGroupHash({groupHash, 32});
    rc = EVP_DigestFinal_ex(evpMdCtx.get(), groupHash, &chSize);
    hexdump(groupHash, "new round group hash");
    assert(rc == 1);
    auto acks = proposalBody.initAcknowledgements(pendingProposalAcks.size());
    auto iter = pendingProposalAcks.begin();
    for (int i = 0; i < pendingProposalAcks.size(); ++i)
    {
        acks[i].setIdx(iter->first);
        acks[i].setSign({reinterpret_cast<const kj::byte*>(iter->second), 64});
        iter++;
    }
    auto data = capnp::messageToFlatArray(proposalBodyBuilder);
    SHA256(data.asBytes().begin(), data.asBytes().size(), proposalHash);
    hexdump(proposalHash, "new round proposal body hash");
    secp256k1_ecdsa_signature sig;
    rc = secp256k1_ecdsa_sign(secpCtx, &sig, proposalHash, seckey, nullptr, nullptr);
    assert(rc == 1);
    uint8_t compSig[64];
    rc = secp256k1_ecdsa_signature_serialize_compact(secpCtx, compSig, &sig);
    assert(rc == 1);
    capnp::MallocMessageBuilder proposalBuilder;
    auto proposal = proposalBuilder.initRoot<proto::Proposal>();
    proposal.setBody({data.asBytes().begin(), data.asBytes().size()});
    proposal.getSign().setSign({compSig, 64});
    proposal.getSign().setIdx(idx);
    pendingProposalAcks.clear();
    rc = secp256k1_ecdsa_sign(secpCtx, &sig, groupHash, seckey, nullptr, nullptr);
    assert(rc == 1);
    rc = secp256k1_ecdsa_signature_serialize_compact(secpCtx, compSig, &sig);
    assert(rc == 1);
    char* d = pendingProposalAcks[idx];
    memcpy(d, compSig, 64);
    for (int i = 0; i < nodesCount; ++i)
    {
        if (i == idx)
        {
            continue;
        }
        sendToNode(i, MessageType::MESSAGE_TYPE_PROPOSAL, proposalBuilder);
    }
}

void
ZyzaReplica::processQuorumCertificate(capnp::MessageBuilder& builder)
{
    auto reader = builder.getRoot<proto::QuorumCertificate>().asReader();
    if (reader.getResponse().getId() != requiredQcReqId)
    {
        std::cout << "wrong quorum req id" << std::endl;
        return;
    }
    if (reader.getSigns().size() != quorumSize)
    {
        std::cout << "wrong quorum size" << std::endl;
        return;
    }
    capnp::MallocMessageBuilder respBodyBuilder;
    respBodyBuilder.setRoot(reader.getResponse());
    auto data = capnp::messageToFlatArray(respBodyBuilder);
    uint8_t hash[32];
    SHA256(data.asBytes().begin(), data.asBytes().size(), hash);
    hexdump(hash, "quorum resp body hash");
    for (const auto& item : reader.getSigns())
    {
        if (item.getSign().size() != 64)
        {
            std::cout << "wrong quorum sign size" << std::endl;
            return;
        }
        secp256k1_ecdsa_signature sig;
        secp256k1_ecdsa_signature_parse_compact(secpCtx, &sig, item.getSign().begin());

        int rc = secp256k1_ecdsa_verify(secpCtx, &sig, hash, &publicKeys[item.getIdx()]);
        if (!rc)
        {
            std::cout << "wrong quorum sign" << std::endl;
            return;
        }
    }
    lastQuorumCertificate.setRoot(reader);
}

void
ZyzaReplica::sendToClient(const std::string& dstIp,
                          uint16_t dstPort,
                          MessageType messageType,
                          std::shared_ptr<capnp::MessageBuilder> message)
{
    /*auto clientSock = loop->resource<uvw::tcp_handle>();
    clientSock->on<uvw::connect_event>(
        [this, messageType, message](uvw::connect_event& e, uvw::tcp_handle& h) {
            MessageHeader header{
                static_cast<uint32_t>(capnp::computeSerializedSizeInWords(*message) * 8 +
                                      sizeof(MessageHeader)),
                static_cast<uint16_t>(idx),
                static_cast<uint16_t>(messageType)};
            auto rc = h.try_write(reinterpret_cast<char*>(&header), sizeof(MessageHeader));
            assert(rc == sizeof(MessageHeader));
            capnp::writeMessageToFd(h.fd(), *message);
            h.close();
        });
    clientSock->connect(dstIp, dstPort);*/
}

void
ZyzaReplica::sendToNode(int node, MessageType messageType, capnp::MessageBuilder& message)
{
    NS_LOG_DEBUG(idx << " " << ns3::Simulator::Now().As(ns3::Time::S) << " sending message "
                     << (int)messageType << " to " << node);
    auto h = activeNodeConnections[node];
    if (h != nullptr)
    {
        uint32_t size = capnp::computeSerializedSizeInWords(message) * 8 + sizeof(MessageHeader);
        auto data = std::make_unique<uint8_t[]>(size);
        new (data.get())
            MessageHeader(size, static_cast<uint16_t>(idx), static_cast<uint16_t>(messageType));
        kj::ArrayOutputStream aoo({reinterpret_cast<uint8_t*>(data.get() + sizeof(MessageHeader)),
                                   size - sizeof(MessageHeader)});
        capnp::writeMessage(aoo, message);
        //        if (h->writable())
        //        {
        h->Send(data.get(), size, 0);
        //        h->write(std::move(data), size);
        //    }
    }
}

bool
ZyzaReplica::isLeader() const
{
    return currentLeader == idx;
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
        activeNodeConnections.emplace_back();
        restartConnectionToNode(i);
    }
}

void
ZyzaReplica::onMessage(std::span<const uint8_t> message)
{
    auto* header = reinterpret_cast<const MessageHeader*>(message.data());
    auto content = message.subspan<sizeof(MessageHeader)>();
    assert(header->messageSize == message.size());
    NS_LOG_DEBUG(idx << " " << ns3::Simulator::Now().As(ns3::Time::S)
                     << " got message: " << header->messageType);
    if (static_cast<MessageType>(header->messageType) == MessageType::MESSAGE_TYPE_REQUEST)
    {
        auto mmb = std::make_unique<capnp::MallocMessageBuilder>();
        capnp::initMessageBuilderFromFlatArrayCopy(
            {reinterpret_cast<const capnp::word*>(content.data()), content.size() / 8},
            *mmb);
        mmb->getRoot<proto::Request>();
        processRequest(std::move(mmb));
    }
    else if (static_cast<MessageType>(header->messageType) == MessageType::MESSAGE_TYPE_PROPOSAL &&
             !isLeader() && header->senderIdx == currentLeader)
    {
        capnp::MallocMessageBuilder mmb;
        capnp::initMessageBuilderFromFlatArrayCopy(
            {reinterpret_cast<const capnp::word*>(content.data()), content.size() / 8},
            mmb);
        processProposal(mmb.getRoot<proto::Proposal>());
    }
    else if (static_cast<MessageType>(header->messageType) == MessageType::MESSAGE_TYPE_ACK &&
             isLeader())
    {
        capnp::MallocMessageBuilder mmb;
        capnp::initMessageBuilderFromFlatArrayCopy(
            {reinterpret_cast<const capnp::word*>(content.data()), content.size() / 8},
            mmb);
        processAcknowledgement(mmb.getRoot<proto::Acknowledgement>());
    }
    else if (static_cast<MessageType>(header->messageType) == MessageType::MESSAGE_TYPE_QC)
    {
        capnp::MallocMessageBuilder mmb;
        capnp::initMessageBuilderFromFlatArrayCopy(
            {reinterpret_cast<const capnp::word*>(content.data()), content.size() / 8},
            mmb);
        mmb.getRoot<proto::QuorumCertificate>();
        processQuorumCertificate(mmb);
    }
}

void
ZyzaReplica::restartConnectionToNode(int i)
{
    NS_LOG_INFO(idx << " " << ns3::Simulator::Now().As(ns3::Time::S) << " restart connection to "
                    << i);
    /*auto con = loop->resource<uvw::tcp_handle>();
    con->on<uvw::error_event>([this, i](auto& a, auto& b) {
        //    std::cout << "connection to " << i << " failed" << std::endl;
        auto t = loop->resource<uvw::timer_handle>();
        t->on<uvw::timer_event>([this, i](auto& a, auto& b) {
            b.stop();
            b.close();
            restartConnectionToNode(i);
        });
        t->start(
            std::chrono::duration_cast<uvw::timer_handle::time>(std::chrono::milliseconds(100)),
            uvw::timer_handle::time(0));
    });
    con->on<uvw::end_event>([this, i](auto& a, auto& b) {
        std::cout << "connection to " << i << " ended" << std::endl;
        //    std::this_thread::sleep_for(std::chrono::milliseconds(100));
        //    restartConnectionToNode(i);
        auto t = loop->resource<uvw::timer_handle>();
        t->on<uvw::timer_event>([this, i](auto& a, auto& b) {
            b.stop();
            b.close();
            restartConnectionToNode(i);
        });
        t->start(
            std::chrono::duration_cast<uvw::timer_handle::time>(std::chrono::milliseconds(100)),
            uvw::timer_handle::time(0));
    });
    con->on<uvw::connect_event>([this, i, w = con->weak_from_this()](auto&, auto& h) {
        if (auto c = w.lock())
        {
            std::cout << "connected to " << h.peer().ip << ":" << h.peer().port << std::endl;
            activeNodeConnections[i] = c;
            h.read();
            if (isLeader())
            {
                sendToNode(i, MessageType::MESSAGE_TYPE_PROPOSAL, initialProposal);
            }
        }
    });
    if (activeNodeConnections[i] != nullptr)
    {
        activeNodeConnections[i]->close();
        activeNodeConnections[i] = nullptr;
    }
    con->connect(nodeList[i].first, nodeList[i].second);*/
    auto con =
        ns3::Socket::CreateSocket(p2psh.GetSpokeNode(idx), ns3::TcpSocketFactory::GetTypeId());
    con->Bind();
    ns3::Address sinkAddress(ns3::InetSocketAddress(p2psh.GetSpokeIpv4Address(i),1234));
//    if (idx < i)
//    {
//        sinkAddress = {ns3::InetSocketAddress(interfaces[idx][i - idx].GetAddress(1), 1234)};
//    }
//    else
//    {
//        sinkAddress = {ns3::InetSocketAddress(interfaces[i][idx - i].GetAddress(0), 1234)};
//    }
    //    con->on<uvw::error_event>([this, i](auto& a, auto& b) {
    //        //    std::cout << "connection to " << i << " failed" << std::endl;
    //        auto t = loop->resource<uvw::timer_handle>();
    //        t->on<uvw::timer_event>([this, i](auto& a, auto& b) {
    //            b.stop();
    //            b.close();
    //            restartConnectionToNode(i);
    //        });
    //        t->start(
    //            std::chrono::duration_cast<uvw::timer_handle::time>(std::chrono::milliseconds(100)),
    //            uvw::timer_handle::time(0));
    //    });
    //    con->on<uvw::end_event>([this, i](auto& a, auto& b) {
    //        std::cout << "connection to " << i << " ended" << std::endl;
    //        //    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    //        //    restartConnectionToNode(i);
    //        auto t = loop->resource<uvw::timer_handle>();
    //        t->on<uvw::timer_event>([this, i](auto& a, auto& b) {
    //            b.stop();
    //            b.close();
    //            restartConnectionToNode(i);
    //        });
    //        t->start(
    //            std::chrono::duration_cast<uvw::timer_handle::time>(std::chrono::milliseconds(100)),
    //            uvw::timer_handle::time(0));
    //    });
    con->SetConnectCallback(
        [this, i](ns3::Ptr<ns3::Socket> con) {
        NS_LOG_INFO(idx << " " << ns3::Simulator::Now().As(ns3::Time::S) << " connected to " << i);
        //            std::cout << "connected to " << h.peer().ip << ":" << h.peer().port <<
        //            std::endl;
        activeNodeConnections[i] = con;
        if (isLeader())
        {
            sendToNode(i, MessageType::MESSAGE_TYPE_PROPOSAL, initialProposal);
        }
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
    //    activeNodeConnections.resize(nodesCount);
    //    for (int i = 0; i < nodesCount; ++i)
    //    {
    //        activeNodeConnections[i] =
    //            ns3::Socket::CreateSocket(nodes.Get(idx), ns3::TcpSocketFactory::GetTypeId());
    //        activeNodeConnections[i]->Bind();
    //        ns3::Address sinkAddress(ns3::InetSocketAddress(interfaces.GetAddress(i), 1234));
    //        activeNodeConnections[i]->Connect(sinkAddress);
    //        if (isLeader())
    //        {
    //            sendToNode(i, MessageType::MESSAGE_TYPE_PROPOSAL, initialProposal);
    //        }
    //    }
}
} // namespace zyza