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

namespace zyza {
NS_LOG_COMPONENT_DEFINE("ZyzaReplica");

ZyzaReplica::ZyzaReplica(
    int nodesCount, int cancelersPerProposal, int idx,
    ns3::PointToPointStarHelper &p2psh,
    std::vector<std::vector<uint8_t>> &serializedPublicKeys,
    std::span<const uint8_t> privateKey,
    std::chrono::milliseconds fallbackTimeout)
    : Endpoint(p2psh.GetSpokeNode(idx)),
      ZyzaCommon(nodesCount, cancelersPerProposal, serializedPublicKeys),
      idx(idx), alertTimeout(fallbackTimeout), currentFastPathLeader(0),
      currentBackupPathLeader(0), initPassed(false), backupFastPathTimeout(),
      proposalOrd(0), p2psh(p2psh) {
  assert(privateKey.size() == 32);
  memcpy(seckey, privateKey.data(), 32);
  assert(secp256k1_ec_seckey_verify(secpCtx, seckey));
  activeNodeConnections.resize(nodesCount);
  sendResendChainRequest();
}

void ZyzaReplica::StartApplication() { Endpoint::run(); }

std::vector<uint8_t>
ZyzaReplica::processRequest(std::span<const uint8_t> request) {
  std::vector<uint8_t> resp(request.size() * 2);
  memcpy(resp.data(), request.data(), request.size());
  memcpy(resp.data() + request.size(), request.data(), request.size());
  return std::move(resp);
}

void ZyzaReplica::onListeningStart() {
  for (int i = 0; i < nodesCount; ++i) {
    restartConnectionToNode(i);
  }
}

void ZyzaReplica::onTcpMessage(std::span<const uint8_t> message) {
  auto *header = reinterpret_cast<const MessageHeader *>(message.data());
  auto content = message.subspan<sizeof(MessageHeader)>();
  assert(header->messageSize == message.size());
  auto messageType = static_cast<MessageType>(header->messageType);
  if (header->senderIdx == 0xffff) {
    return;
  }
  std::clog << ns3::Simulator::Now().As() << ": " << idx
            << ": got message: " << messageTypeToString(messageType) << " from "
            << header->senderIdx << " msgId: " << std::hex << header->msgId
            << std::dec << std::endl;
  capnp::FlatArrayMessageReader reader(
      {reinterpret_cast<const capnp::word *>(content.data()),
       content.size() / 8});
  switch (messageType) {
  case MessageType::PROPOSAL:
    processProposal(reader.getRoot<proto::Proposal>());
    break;
  case MessageType::PROPOSAL_ACK:
    processAcknowledgement(reader.getRoot<proto::Acknowledgement>());
    break;
  case MessageType::FALLBACK_ALERT:
    processFallbackAlert(reader.getRoot<proto::SignedMessage>());
    break;
  case MessageType::PROPOSAL_CANCEL_REQUEST:
    processProposalCancelRequest(
        reader.getRoot<proto::SignedMessage>());
    break;
  case MessageType::PROPOSAL_CANCEL_RESPONSE:
    processProposalCancelResponse(reader.getRoot<proto::SignedMessage>());
    break;
  case MessageType::RECOVERY:
    processRecovery(reader.getRoot<proto::SignedMessage>());
    break;
  case MessageType::RECOVERY_ACK:
    processRecoveryAck(reader.getRoot<proto::RecoveryAck>());
    break;
  case MessageType::RESEND_CHAIN_REQUEST:
    processResendChainRequest(reader.getRoot<proto::ResendChainRequest>());
    break;
  case MessageType::RESEND_CHAIN_RESPONSE:
    processResendChainResponse(reader.getRoot<proto::ResendChainResponse>());
    break;
  default:
    break;
  }
}

void ZyzaReplica::onUdpMessage(std::span<const uint8_t> message) {
  auto *header = reinterpret_cast<const MessageHeader *>(message.data());
  auto content = message.subspan<sizeof(MessageHeader)>();
  assert(header->messageSize == message.size());
  auto messageType = static_cast<MessageType>(header->messageType);
  if (header->senderIdx != 0xffff) {
    return;
  }
  std::clog << ns3::Simulator::Now().As() << ": " << idx
            << ": got message: " << messageTypeToString(messageType) << " from "
            << header->senderIdx << " msgId: " << std::hex << header->msgId
            << std::dec << std::endl;
  capnp::FlatArrayMessageReader reader(
      {reinterpret_cast<const capnp::word *>(content.data()),
       content.size() / 8});
  switch (messageType) {
  case MessageType::REQUEST:
    processRequest(reader.getRoot<proto::Request>());
    break;
  case MessageType::CLIENT_RESPONSE:
    processClientResponse(reader.getRoot<proto::ClientResponse>());
    break;
  default:
    break;
  }
}

void ZyzaReplica::processRequest(const proto::Request::Reader &request) {
  if (currentState == ReplicaState::LEADER_FAST) {
    for (auto &req : pendingRequests) {
      if (req->getRoot<proto::Request>().getId() == request.getId()) {
        std::clog << "got request with existing id" << std::endl;
        return;
      }
    }
    pendingRequests.emplace_back(new capnp::MallocMessageBuilder())
        ->setRoot(request);
    onRequestAccepted();
  } else {
    capnp::MallocMessageBuilder redirectBuilder;
    auto redirect = redirectBuilder.initRoot<proto::Redirect>();
    redirect.setRedirect(currentFastPathLeader);
    sendToClient(request.getRespAddr(), request.getRespPort(),
                 MessageType::REDIRECT_REQUEST, redirectBuilder);
  }
}

void ZyzaReplica::processClientResponse(
    const proto::ClientResponse::Reader &reader) {
  bool isACanceler = false;
  if (reader.getProposalHash().size() != 32) {
    std::clog << "wrong proposal hash size" << std::endl;
    return;
  }
  for (const auto &nodeIdx :
       getProposalCancelers(reader.getProposalHash().begin())) {
    if (nodeIdx == idx) {
      isACanceler = true;
    }
  }
  if (!isACanceler) {
    std::clog << "wrong client response destination" << std::endl;
    return;
  }
  if (reader.which() == proto::ClientResponse::COMPLETED) {
    for (const auto &item : reader.getCompleted()) {
      if (item.getSign().size() != 64) {
        std::clog << "wrong sign size" << std::endl;
        return;
      }
    }
  }
  for (auto &pendingRequest : pendingProposalCancelRequests) {
    if (memcmp(pendingRequest.proposalHash, reader.getProposalHash().begin(),
               32) != 0) {
      continue;
    }
    if (pendingRequest.clientResponses.contains(reader.getId())) {
      std::clog << "already has client response" << std::endl;
      return;
    }
    pendingRequest.clientResponses
        .emplace(reader.getId(),
                 std::make_unique<capnp::MallocMessageBuilder>())
        .first->second->setRoot(reader);
    if (pendingRequest.clientResponses.size() == pendingRequest.clientCount) {
      for (const auto &nodeIdx : pendingRequest.reporters) {
        sendProposalCancelResponse(pendingRequest, nodeIdx);
      }
    }
    return;
  }
  auto &pendingRequest = pendingProposalCancelRequests.emplace_back();
  memcpy(pendingRequest.proposalHash, reader.getProposalHash().begin(), 32);
  pendingRequest.clientResponses
      .emplace(reader.getId(), std::make_unique<capnp::MallocMessageBuilder>())
      .first->second->setRoot(reader);
}

void ZyzaReplica::processProposal(const proto::Proposal::Reader &proposal) {
  if (currentState != ReplicaState::BACKUP_FAST) {
    return;
  }
  for (const auto &ackList : proposal.getAcknowledgements()) {
    if (pendingChain.empty()) {
      std::clog << "got acks for unknown proposal" << std::endl;
      return;
    }
    if (!validateAckList(pendingChain.front().proposalHash, ackList)) {
      return;
    }
    auto &acceptedProposal =
        acceptedChain.emplace_back(std::move(pendingChain.front()));
    for (const auto &sign : ackList) {
      memcpy(acceptedProposal.acks[sign.getIdx()], sign.getSign().begin(), 64);
    }
    pendingProposals.pop_front();
    std::clog << "processed ack list" << std::endl;
  }
  if (pendingProposals.size() == maxPendingChainLength) {
    std::clog << "pending tail size is too long" << std::endl;
    return;
  }
  capnp::FlatArrayMessageReader proposalSignedMessageReader(
      {reinterpret_cast<const capnp::word *>(
           proposal.getSignedProposal().begin()),
       proposal.getSignedProposal().size() / sizeof(capnp::word)});
  auto proposalSignedMessage =
      proposalSignedMessageReader.getRoot<proto::SignedMessage>();
  if (!validateProposal(proposalSignedMessage, pendingChain.back().proposalHash,
                        initPassed ? currentFastPathLeader : 0, initPassed)) {
    return;
  }
  capnp::FlatArrayMessageReader bodyMessage(
      {reinterpret_cast<const capnp::word *>(
           proposalSignedMessage.getBody().begin()),
       proposalSignedMessage.getBody().size() / 8});
  auto body = bodyMessage.getRoot<proto::ProposalBody>();
  std::clog << idx << ": got valid proposal with ord " << body.getOrd()
            << std::endl;
  uint8_t newProposalHash[32];
  SHA256(proposal.getSignedProposal().asBytes().begin(),
         proposal.getSignedProposal().asBytes().size(), newProposalHash);
  {
    auto &pendingBlock = pendingChain.emplace_back();
    memcpy(pendingBlock.proposalHash, newProposalHash, 32);
    pendingBlock.proposal.assign(
        proposalSignedMessage.getBody().asBytes().begin(),
        proposalSignedMessage.getBody().asBytes().end());
  }
  for (const auto &item : body.getRequests()) {
    responseToClient(item, newProposalHash);
  }
  auto cancelers = getProposalCancelers(newProposalHash);
  if (!cancelers.contains(idx)) {
    uint8_t compressedSig[64];
    signData(newProposalHash, compressedSig);
    capnp::MallocMessageBuilder ackBuilder;
    auto ack = ackBuilder.initRoot<proto::Acknowledgement>();
    ack.setProposalHash({newProposalHash, 32});
    ack.getSign().setSign({compressedSig, 64});
    ack.getSign().setIdx(idx);
    sendToNode(currentFastPathLeader, MessageType::PROPOSAL_ACK, ackBuilder);
    for (const auto &nodeIdx : cancelers) {
      sendToNode(nodeIdx, MessageType::PROPOSAL_ACK, ackBuilder);
    }
  }
  backupFastPathTimeout.Cancel();
  backupFastPathTimeout = ns3::Simulator::Schedule(
      ns3::Time::From(alertTimeout.count(), ns3::Time::MS),
      [this] { handleTimeout(); });
  initPassed = true;
  proposalOrd++;
  std::clog << "processed proposal" << std::endl;
}

void ZyzaReplica::processAcknowledgement(
    const proto::Acknowledgement::Reader &reader) {
  if (currentState != ReplicaState::LEADER_FAST) {
    return;
  }
  if (reader.getProposalHash().size() != 32) {
    std::clog << "wrong ack proposal hash size" << std::endl;
    return;
  }
  if (reader.getSign().getSign().size() != 64) {
    std::clog << "wrong ack proposal sign size" << std::endl;
    return;
  }
  if (!verifyData(reader.getProposalHash().begin(),
                  reader.getSign().getSign().begin(),
                  reader.getSign().getIdx())) {
    std::clog << "wrong ack proposal sign" << std::endl;
    return;
  }
  for (auto &proposal : pendingProposals) {
    if (memcmp(proposal.proposalHash, reader.getProposalHash().begin(), 32) !=
        0) {
      continue;
    }
    auto cancelers = getProposalCancelers(proposal.proposalHash);
    if (cancelers.contains(reader.getSign().getIdx())) {
      if (proposal.acks.size() == quorumSize) {
        return;
      }
    } else {
      int collectedCancelerAcks = 0;
      for (const auto &nodeIdx : cancelers) {
        if (proposal.acks.contains(nodeIdx)) {
          collectedCancelerAcks++;
        }
      }
      if (proposal.acks.size() - collectedCancelerAcks ==
          quorumSize - cancelersPerProposal) {
        return;
      }
    }
    memcpy(proposal.acks[reader.getSign().getIdx()],
           reader.getSign().getSign().begin(), 64);
    std::clog << "processed ack" << std::endl;
    break;
  }
  if (pendingProposals.begin()->acks.size() == quorumSize) {
    onPendingBlockAcksReady();
  }
}

void ZyzaReplica::processFallbackAlert(
    const proto::SignedMessage::Reader &fallbackAlert) {
  if (currentState != ReplicaState::LEADER_FALLBACK) {
    return;
  }
  if (!verifySignedMessage(fallbackAlert)) {
    return;
  }
  capnp::FlatArrayMessageReader signedMessageReader(
      {reinterpret_cast<const capnp::word *>(fallbackAlert.getBody().begin()),
       fallbackAlert.getBody().size() / 8});
  auto fallbackAlertBody =
      signedMessageReader.getRoot<proto::FallbackAlertBody>();
  if (fallbackAlertBody.getLastAckedProposalHash().size() != 32) {
    std::clog << "wrong fallback alert last acked proposal hash size"
              << std::endl;
    return;
  }
  if (memcmp(fallbackAlertBody.getLastAckedProposalHash().begin(),
             acceptedChain.back().proposalHash, 32) != 0) {
    std::clog << "wrong fallback alert last acked proposal hash" << std::endl;
    capnp::MallocMessageBuilder resendChainRequestBuilder;
    auto resendChainRequest =
        resendChainRequestBuilder.initRoot<proto::ResendChainRequest>();
    resendChainRequest.setIdx(fallbackAlert.getSign().getIdx());
    resendChainRequest.setLastAckedProposalHash(
        fallbackAlertBody.getLastAckedProposalHash());
    processResendChainRequest(resendChainRequest);
    return;
  }
  capnp::MallocMessageBuilder resendChainResponseBuilder;
  auto resendChainResponse =
      resendChainResponseBuilder.initRoot<proto::ResendChainResponse>();
  resendChainResponse.setProposals(
      fallbackAlertBody.getUnackedSignedProposals());
  resendChainResponse.initAcknowledgements(0);
  if (!validateResendChainResponse(resendChainResponse)) {
    return;
  }
  int i = 0;
  for (const auto &proposal : fallbackAlertBody.getUnackedSignedProposals()) {
    capnp::FlatArrayMessageReader proposalSignedMessageReader(
        {reinterpret_cast<const capnp::word *>(proposal.begin()),
         proposal.size() / 8});
    auto proposalSignedMessage =
        proposalSignedMessageReader.getRoot<proto::SignedMessage>();
    capnp::FlatArrayMessageReader proposalBodyReader(
        {reinterpret_cast<const capnp::word *>(
             proposalSignedMessage.getBody().begin()),
         proposalSignedMessage.getBody().size() / 8});
    auto proposalBody = proposalBodyReader.getRoot<proto::ProposalBody>();

  }
}

void ZyzaReplica::processProposalCancelRequest(
    const proto::SignedMessage::Reader &proposalCancelRequest) {
  if (proposalCancelRequest.getIdx() >= nodesCount) {
    std::clog << "wrong node idx" << std::endl;
    return;
  }
  uint8_t proposalHash[32];
  SHA256(proposalCancelRequest.getSignedProposal().asBytes().begin(),
         proposalCancelRequest.getSignedProposal().asBytes().size(),
         proposalHash);
  auto it = pendingProposalCancelRequests.begin();
  std::map<uint64_t, std::unique_ptr<capnp::MallocMessageBuilder>>
      clientResponses;
  std::set<uint16_t> reporters;
  while (it != pendingProposalCancelRequests.end()) {
    auto &pendingRequest = *it;
    if (memcmp(pendingRequest.proposalHash, proposalHash, 32) == 0) {
      if (pendingRequest.clientCount == 0) {
        clientResponses = std::move(pendingRequest.clientResponses);
        reporters = std::move(pendingRequest.reporters);
        pendingProposalCancelRequests.erase(it);
        break;
      }
      if (pendingRequest.clientResponses.size() == pendingRequest.clientCount) {
        sendProposalCancelResponse(pendingRequest,
                                   proposalCancelRequest.getIdx());
      } else {
        pendingRequest.reporters.insert(proposalCancelRequest.getIdx());
      }
      return;
    }
  }
  if (!getProposalCancelers(proposalHash).contains(idx)) {
    std::clog << "this node is not a canceler for provided proposal"
              << std::endl;
    return;
  }
  capnp::FlatArrayMessageReader proposalSignedMessageReader(
      {reinterpret_cast<const capnp::word *>(
           proposalCancelRequest.getSignedProposal().begin()),
       proposalCancelRequest.getSignedProposal().size() / sizeof(capnp::word)});
  auto proposalSignedMessage =
      proposalSignedMessageReader.getRoot<proto::SignedMessage>();
  if (!validateProposal(proposalSignedMessage, nullptr, -1, -1)) {
    return;
  }
  capnp::FlatArrayMessageReader proposalBodyReader(
      {reinterpret_cast<const capnp::word *>(
           proposalSignedMessage.getBody().begin()),
       proposalSignedMessage.getBody().size() / sizeof(capnp::word)});
  auto proposalBody = proposalBodyReader.getRoot<proto::ProposalBody>();
  if (proposalBody.getRequests().size() !=
      proposalCancelRequest.getSignatures().size()) {
    std::clog << "wrong cancel request signatures list size" << std::endl;
    return;
  }
  std::vector<std::unique_ptr<capnp::MallocMessageBuilder>> cancelRequests;
  for (int i = 0; i < proposalBody.getRequests().size(); ++i) {
    auto request = proposalBody.getRequests()[i];
    auto requestCancel =
        cancelRequests
            .emplace_back(std::make_unique<capnp::MallocMessageBuilder>())
            ->initRoot<proto::RequestCancel>();
    requestCancel.setId(request.getId());
    requestCancel.setProposalHash({proposalHash, 32});
    uint8_t cancelProof[8 + 32];
    *reinterpret_cast<uint64_t *>(cancelProof) = request.getId();
    memcpy(cancelProof + 8, proposalHash, 32);
    uint8_t cancelHash[32];
    SHA256(cancelProof, 8 + 32, cancelHash);
    if (proposalCancelRequest.getSignatures()[i].size() != quorumSize) {
      std::clog << "wrong signature list size" << std::endl;
    }
    for (const auto &sign : proposalCancelRequest.getSignatures()[i]) {
      if (sign.getSign().size() != 64) {
        std::clog << "wrong sign size" << std::endl;
        return;
      }
      if (!verifyData(cancelHash, sign.getSign().begin(), sign.getIdx())) {
        std::clog << "wrong sign" << std::endl;
        return;
      }
    }
    requestCancel.setSignatures(proposalCancelRequest.getSignatures()[i]);
  }
  auto &pendingCancelRequest = pendingProposalCancelRequests.emplace_back();
  memcpy(pendingCancelRequest.proposalHash, proposalHash, 32);
  pendingCancelRequest.reporters = std::move(reporters);
  pendingCancelRequest.reporters.insert(proposalCancelRequest.getIdx());
  pendingCancelRequest.clientResponses = std::move(clientResponses);
  pendingCancelRequest.clientCount = proposalBody.getRequests().size();
  for (int i = 0; i < proposalBody.getRequests().size(); ++i) {
    auto request = proposalBody.getRequests()[i];
    sendToClient(request.getRespAddr(), request.getRespPort(),
                 MessageType::REQUEST_CANCEL, *cancelRequests[i]);
  }
}

void ZyzaReplica::processProposalCancelResponse(
    const proto::SignedMessage::Reader &proposalCancelResponse) {
  -- --;
}

void ZyzaReplica::processRecovery(const proto::SignedMessage::Reader &recovery) {
  assert(initPassed);
  uint16_t expectedLeader = 0;
  uint8_t expectedHash[32];
  {
    auto proposal = lastUnackedProposal.getRoot<proto::Proposal>();
    expectedLeader = proposal.getSign().getIdx();
    capnp::FlatArrayMessageReader reader(
        {reinterpret_cast<const capnp::word *>(
             proposal.getBody().asBytes().begin()),
         proposal.getBody().asBytes().size() / 8});
    memcpy(expectedHash,
           reader.getRoot<proto::ProposalBody>().getPrevProposalHash().begin(),
           32);
  }
  if (recovery.getProof().size() != quorumSize) {
    std::clog << "wrong proof size" << std::endl;
    return;
  }
  std::map<uint64_t, std::pair<bool, capnp::MallocMessageBuilder>>
      requestStatus;
  std::vector<uint8_t[32]> proposalHashes(recovery.getProof().size());
  auto proposalHashesIter = proposalHashes.begin();
  for (const auto &item : recovery.getProof()) {
    capnp::FlatArrayMessageReader reader(
        {reinterpret_cast<const capnp::word *>(
             item.getUnackedProposal().asBytes().begin()),
         item.getUnackedProposal().asBytes().size() / 8});
    auto proposal = reader.getRoot<proto::Proposal>();
    if (!validateProposal(proposal, expectedHash, expectedLeader, true,
                          proposalOrd)) {
      std::clog << "wrong recovery proof proposal" << std::endl;
      return;
    }
    if (!verifyData(item.getUnackedProposal(), item.getSign())) {
      std::clog << "wrong recovery proof sign" << std::endl;
      return;
    }
    capnp::FlatArrayMessageReader bodyReader(
        {reinterpret_cast<const capnp::word *>(
             proposal.getBody().asBytes().begin()),
         proposal.getBody().asBytes().size() / 8});
    for (const auto &req :
         bodyReader.getRoot<proto::ProposalBody>().getRequests()) {
      auto reqId = req.getId();
      if (requestStatus.contains(reqId)) {
        continue;
      }
      requestStatus[reqId].first = false;
      requestStatus[reqId].second.setRoot(req);
    }
    SHA256(proposal.getBody().asBytes().begin(),
           proposal.getBody().asBytes().size(), *proposalHashesIter);
    proposalHashesIter++;
  }
  int proposalForQc = -1;
  switch (recovery.which()) {
  case proto::Recovery::CLIENT_RESPONSES: {
    for (const auto &cr : recovery.getClientResponses()) {
      uint64_t reqId = cr.getReqId();
      if (requestStatus[reqId].first) {
        std::clog << "duplicate client response" << std::endl;
        return;
      }
      auto &reqPair = requestStatus[reqId];
      auto request = reqPair.second.getRoot<proto::Request>();
      if (cr.getDropSecret().size() != 32) {
        std::clog << "wrong drop secret size" << std::endl;
        return;
      }
      uint8_t dropSecretHash[32];
      SHA256(cr.getDropSecret().begin(), 32, dropSecretHash);
      if (memcmp(dropSecretHash, request.getDropHash().begin(), 32) != 0) {
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
    if (requestStatus[reqId].first) {
      std::clog << "duplicate client response" << std::endl;
      return;
    }
    auto &reqPair = requestStatus[reqId];
    if (!validateQuorumCertificate(qc, nullptr)) {
      std::clog << "wrong quorum certificate" << std::endl;
      return;
    }
    reqPair.first = true;
    for (int i = 0; i < proposalHashes.size(); ++i) {
      if (memcmp(proposalHashes[i], qc.getResponse().getProposalHash().begin(),
                 32) == 0) {
        proposalForQc = i;
      }
    }
    break;
  }
  }
  if (proposalForQc == -1) {
    proposalForQc = 0;
  }
  auto acceptedProposalData =
      recovery.getProof()[proposalForQc].getUnackedProposal().asBytes();
  capnp::FlatArrayMessageReader proposalReader(
      {reinterpret_cast<const capnp::word *>(acceptedProposalData.begin()),
       acceptedProposalData.size() / 8});
  recoverWithProposal(proposalReader.getRoot<proto::Proposal>());
}

void ZyzaReplica::processRecoveryAck(
    const proto::RecoveryAck::Reader &recoveryAck) {
  -- --;
}

void ZyzaReplica::processResendChainRequest(
    const proto::ResendChainRequest::Reader &nsr) {
  if (nsr.getLastAckedProposalHash().size() != 32) {
    std::clog << "wrong resend chain proposal hash size" << std::endl;
    return;
  }
  if (nsr.getIdx() >= nodesCount) {
    std::clog << "wrong resend chain node idx" << std::endl;
    return;
  }
  if (acceptedChain.empty()) {
    return;
  }
  uint8_t zeroHash[32];
  memset(zeroHash, 0, 32);
  std::list<Proposal>::iterator pendingBegin;
  std::list<Proposal>::iterator pendingEnd;
  int pendingTotalSize;
  if (currentState == ReplicaState::LEADER_FAST) {
    pendingBegin = pendingProposals.begin();
    pendingEnd = pendingProposals.end();
    pendingTotalSize = pendingProposals.size();
  } else {
    pendingBegin = pendingChain.begin();
    pendingEnd = pendingChain.end();
    pendingTotalSize = pendingChain.size();
  }
  if (memcmp(zeroHash, nsr.getLastAckedProposalHash().begin(), 32) == 0) {
    resendChainPart(nsr.getIdx(), acceptedChain.begin(), acceptedChain.size(),
                    pendingBegin, pendingTotalSize);
    return;
  }
  int pendingSize = 0;
  if (pendingBegin != pendingEnd) {
    do {
      pendingEnd--;
      pendingSize++;
      if (memcmp(pendingEnd->proposalHash,
                 nsr.getLastAckedProposalHash().begin(), 32) == 0) {
        pendingEnd++;
        pendingSize--;
        resendChainPart(nsr.getIdx(), acceptedChain.end(), 0, pendingEnd,
                        pendingSize);
        return;
      }
    } while (pendingBegin != pendingEnd);
  }
  int acceptedSize = 0;
  auto acceptedEnd = acceptedChain.begin();
  if (acceptedChain.begin() != acceptedEnd) {
    do {
      pendingEnd--;
      acceptedSize++;
      if (memcmp(acceptedEnd->proposalHash,
                 nsr.getLastAckedProposalHash().begin(), 32) == 0) {
        acceptedEnd++;
        acceptedSize--;
        resendChainPart(nsr.getIdx(), acceptedEnd, acceptedSize, pendingBegin,
                        pendingTotalSize);
        return;
      }
    } while (acceptedChain.begin() != acceptedEnd);
  }
}

void ZyzaReplica::processResendChainResponse(
    const proto::ResendChainResponse::Reader &nsr) {
  if (currentState != ReplicaState::BACKUP_FALLBACK) {
    return;
  }
  if (!validateResendChainResponse(nsr)) {
    return;
  }
  auto proposalsIt = nsr.getProposals().begin();
  auto proposalsEnd = nsr.getProposals().end();
  auto acksIt = nsr.getAcknowledgements().begin();
  auto acksEnd = nsr.getAcknowledgements().end();
  proposalsIt = nsr.getProposals().begin();
  acksIt = nsr.getAcknowledgements().begin();
  auto pendingIt = pendingChain.begin();
  auto pendingEnd = pendingChain.end();
  bool appended = false;
  while (proposalsIt != proposalsEnd && acksIt != acksEnd &&
         pendingIt != pendingEnd) {
    if (proposalsIt->size() != pendingIt->proposal.size() ||
        memcmp(proposalsIt->begin(), pendingIt->proposal.data(),
               proposalsIt->size()) != 0) {
      pendingChain.clear();
      appendTail(proposalsIt, proposalsEnd, acksIt, acksEnd);
      appended = true;
      break;
    }
    auto &newAcceptedProposal =
        acceptedChain.emplace_back(std::move(pendingChain.front()));
    pendingChain.pop_front();
    for (const auto &item : *acksIt) {
      memcpy(newAcceptedProposal.acks[item.getIdx()], item.getSign().begin(),
             64);
    }
  }
  if (pendingIt == pendingEnd) {
    appendTail(proposalsIt, proposalsEnd, acksIt, acksEnd);
    appended = true;
  } else {
    bool diverged = false;
    while (proposalsIt != proposalsEnd && pendingIt != pendingEnd) {
      if (proposalsIt->size() != pendingIt->proposal.size() ||
          memcmp(proposalsIt->begin(), pendingIt->proposal.data(),
                 proposalsIt->size()) != 0) {
        diverged = true;
        break;
      }
    }
    if (!diverged) {
      if (proposalsIt != proposalsEnd) {
        appendTail(proposalsIt, proposalsEnd, acksIt, acksEnd);
        appended = true;
      }
    }
  }
  if (appended) {
    transitionToBackupFastPath();
  }
}

void ZyzaReplica::transitionToNextBackupLeader() {
  currentBackupPathLeader = (currentBackupPathLeader + 1) % nodesCount;
  sendFallbackAlert(currentBackupPathLeader);
  capnp::MallocMessageBuilder resendChainRequestBuilder;
  auto resendChainRequest =
      resendChainRequestBuilder.initRoot<proto::ResendChainRequest>();
  resendChainRequest.setIdx(idx);
  resendChainRequest.setLastAckedProposalHash(
      {acceptedChain.back().proposalHash, 32});
  int a = currentFastPathLeader;
  while (a != currentBackupPathLeader) {
    sendToNode(a, MessageType::RESEND_CHAIN_REQUEST, resendChainRequestBuilder);
    a++;
  }
  if (currentState == ReplicaState::BACKUP_FAST) {
    backupFastPathTimeout.Cancel();
  }
  currentState = ReplicaState::BACKUP_FALLBACK;
  nextLeaderAlertTimerEvent.Cancel();
  nextLeaderAlertTimerEvent = ns3::Simulator::Schedule(
      ns3::Time::From(leaderSwitchTimeout.count(), ns3::Time::MS),
      [this] { handleTimeout(); });
}

void ZyzaReplica::transitionToLeaderFallbackPath() {
  if (currentState == ReplicaState::BACKUP_FAST) {
    backupFastPathTimeout.Cancel();
  } else if (currentState == ReplicaState::BACKUP_FALLBACK) {
    recoveryMessageBuilder = nullptr;
    recoveryAcks.clear();
  }
  currentState = ReplicaState::LEADER_FALLBACK;
  -- --;
}

void ZyzaReplica::transitionToBackupFastPath() {
  currentState = ReplicaState::BACKUP_FAST;
  capnp::FlatArrayMessageReader reader(
      {reinterpret_cast<const capnp::word *>(
           acceptedChain.back().proposal.data()),
       acceptedChain.back().proposal.size() / 8});
  currentFastPathLeader =
      reader.getRoot<proto::SignedMessage>().getSign().getIdx();
  backupFastPathTimeout.Cancel();
  backupFastPathTimeout = ns3::Simulator::Schedule(
      ns3::Time::From(alertTimeout.count(), ns3::Time::MS),
      [this] { handleTimeout(); });

  recoveryMessageBuilder = nullptr;
  memset(recoveryMessageHash, 0, 32);
  recoveryAcks.clear();
  nextLeaderAlertTimerEvent.Cancel();
}

void ZyzaReplica::onPendingBlockAcksReady() {
  if (pendingRequests.empty()) {
    return;
  }
  startNewRound();
}

void ZyzaReplica::onRequestAccepted() {
  if (pendingProposals.size() == maxPendingChainLength &&
      pendingProposals.begin()->acks.size() != quorumSize) {
    return;
  }
  startNewRound();
}

void ZyzaReplica::startNewRound() {
  auto t = ns3::Simulator::Now();
  if (sumCount == 0) {
    start = ns3::Simulator::Now();
  }
  sumCount++;
  std::clog << "t: " << (t - last).As(ns3::Time::S) << std::endl;
  std::clog << "avg(" << sumCount
            << "): " << ((t - start) / sumCount).As(ns3::Time::S) << std::endl;
  std::clog << "sent: " << sentStatistics << std::endl;
  std::clog << "sent pkt size: " << sentMsgSize << std::endl;
  std::clog << "recv: " << recvStatistics << std::endl;
  std::clog << "recv pkt size: " << recvMsgSize << std::endl;
  sentStatistics = 0;
  recvStatistics = 0;
  last = t;

  std::clog << "starting a new round" << std::endl;
  capnp::MallocMessageBuilder proposalBodyBuilder;
  auto proposalBody = proposalBodyBuilder.initRoot<proto::ProposalBody>();
  proposalBody.setPrevProposalHash({pendingProposals.back().proposalHash, 32});
  proposalBody.initRequests(pendingRequests.size());
  for (int i = 0; i < pendingRequests.size(); ++i) {
    proposalBody.getRequests().setWithCaveats(
        i, pendingRequests[i]->getRoot<proto::Request>());
  }
  proposalBody.setOrd(proposalOrd);
  proposalOrd++;
  capnp::MallocMessageBuilder signedProposalBuilder;
  createSignedMessage(proposalBodyBuilder, signedProposalBuilder);

  auto signedProposal = signedProposalBuilder.getRoot<proto::SignedMessage>();
  auto serializedSignedProposal =
      capnp::messageToFlatArray(signedProposalBuilder);
  uint8_t proposalHash[32];
  SHA256(serializedSignedProposal.asBytes().begin(),
         serializedSignedProposal.asBytes().size(), proposalHash);
  hexdump(proposalHash, "new round proposal hash");

  for (const auto &pendingRequest : pendingRequests) {
    responseToClient(pendingRequest->getRoot<proto::Request>(), proposalHash);
  }
  pendingRequests.clear();

  capnp::MallocMessageBuilder proposalBuilder;
  auto proposal = proposalBuilder.initRoot<proto::Proposal>();
  proposal.setSignedProposal(serializedSignedProposal.asBytes());
  {
    int acceptedProposals = 0;
    auto it = pendingProposals.begin();
    while (it != pendingProposals.end()) {
      if (it->acks.size() != quorumSize) {
        break;
      }
      acceptedProposals++;
      it++;
    }
    if (acceptedProposals != 0) {
      proposal.initAcknowledgements(acceptedProposals);
    }
    it = pendingProposals.begin();
    for (int i = 0; i < acceptedProposals; ++i) {
      auto d = proposal.getAcknowledgements().init(i, quorumSize);
      int j = 0;
      for (const auto &item : it->acks) {
        auto signature = d[j];
        signature.setIdx(item.first);
        signature.setSign({item.second, 64});
        j++;
      }
      it++;
    }
    for (int i = 0; i < acceptedProposals; ++i) {
      acceptedChain.emplace_back(std::move(pendingProposals.front()));
      pendingProposals.pop_front();
      initPassed = true;
    }
  }

  for (int i = 0; i < nodesCount; ++i) {
    if (i == idx) {
      continue;
    }
    sendToNode(i, MessageType::PROPOSAL, proposalBuilder);
  }

  auto &newPendingProposal = pendingProposals.emplace_back();
  memcpy(newPendingProposal.proposalHash, proposalHash, 32);
  newPendingProposal.proposal.assign(serializedSignedProposal.asBytes().begin(),
                                     serializedSignedProposal.asBytes().end());
  signData(proposalHash, newPendingProposal.acks[idx]);
  std::clog << "started a new round" << std::endl;
}

void ZyzaReplica::responseToClient(const proto::Request::Reader &request,
                                   uint8_t *proposalHash) {
  capnp::MallocMessageBuilder respBodyBuilder;
  auto respBody = respBodyBuilder.initRoot<proto::ResponseBody>();
  respBody.setId(request.getId());
  auto respImpl = processRequest(request.getImpl());
  respBody.setImpl({respImpl.data(), respImpl.size()});
  respBody.setProposalHash({proposalHash, 32});
  capnp::MallocMessageBuilder respBuilder;
  createSignedMessage(respBodyBuilder, respBuilder);
  sendToClient(request.getRespAddr().cStr(), request.getRespPort(),
               MessageType::RESPONSE, respBuilder);
}

void ZyzaReplica::resendChainPart(
    int nodeIdx, std::list<Proposal>::iterator acceptedChainIter,
    int acceptedChainPartSize, std::list<Proposal>::iterator pendingChainIter,
    int pendingChainPartSize) {
  capnp::MallocMessageBuilder resendChainResponseBuilder;
  auto resendChainResponse =
      resendChainResponseBuilder.initRoot<proto::ResendChainResponse>();
  auto proposals = resendChainResponse.initProposals(acceptedChainPartSize +
                                                     pendingChainPartSize);
  auto acks = resendChainResponse.initAcknowledgements(acceptedChainPartSize);
  int i = 0;
  while (acceptedChainIter != acceptedChain.end()) {
    proposals.set(i, {acceptedChainIter->proposal.data(),
                      acceptedChainIter->proposal.size()});
    auto acksArr = acks.init(i, quorumSize);
    int j = 0;
    for (const auto &[nodeId, sig] : acceptedChainIter->acks) {
      acksArr[j].setIdx(nodeId);
      acksArr[j].setSign({sig, 64});
    }
    i++;
    acceptedChainIter++;
  }
  if (currentState == ReplicaState::LEADER_FAST) {
    while (pendingChainIter != pendingProposals.end()) {
      proposals.set(i, {pendingChainIter->proposal.data(),
                        pendingChainIter->proposal.size()});
      i++;
      pendingChainIter++;
    }
  } else {
    while (pendingChainIter != pendingChain.end()) {
      proposals.set(i, {pendingChainIter->proposal.data(),
                        pendingChainIter->proposal.size()});
      i++;
      pendingChainIter++;
    }
  }
  sendToNode(nodeIdx, MessageType::RESEND_CHAIN_RESPONSE,
             resendChainResponseBuilder);
}

void ZyzaReplica::sendProposalCancelResponse(
    ZyzaReplica::PendingProposalCancelRequest &pendingRequest,
    uint16_t nodeIdx) {
  capnp::MallocMessageBuilder scrbBuilder;
  auto pcrb = scrbBuilder.initRoot<proto::ProposalCancelResponseBody>();
  pcrb.setProposalHash({pendingRequest.proposalHash, 32});
  auto clientResponses = pcrb.initClientResponses(pendingRequest.clientCount);
  auto it = pendingRequest.clientResponses.begin();
  for (int i = 0; i < pendingRequest.clientCount; ++i) {
    clientResponses.setWithCaveats(
        i, it->second->getRoot<proto::ClientResponse>());
    it++;
  }
  capnp::MallocMessageBuilder signedMessage;
  createSignedMessage(scrbBuilder, signedMessage);
  sendToNode(nodeIdx, MessageType::PROPOSAL_CANCEL_RESPONSE, signedMessage);
}

void ZyzaReplica::appendTail(
    capnp::List<capnp::Data>::Reader::Iterator proposalsIt,
    capnp::List<capnp::Data>::Reader::Iterator proposalsEnd,
    capnp::List<capnp::List<proto::Signature>>::Reader::Iterator acksIt,
    capnp::List<capnp::List<proto::Signature>>::Reader::Iterator acksEnd) {
  while (proposalsIt != proposalsEnd && acksIt != acksEnd) {
    auto &newAcceptedProposal = acceptedChain.emplace_back();
    newAcceptedProposal.proposal.assign(proposalsIt->begin(),
                                        proposalsIt->end());
    SHA256(newAcceptedProposal.proposal.data(),
           newAcceptedProposal.proposal.size(),
           newAcceptedProposal.proposalHash);
    for (const auto &item : *acksIt) {
      memcpy(newAcceptedProposal.acks[item.getIdx()], item.getSign().begin(),
             64);
    }
    capnp::FlatArrayMessageReader signedMessageReader(
        {reinterpret_cast<const capnp::word *>(proposalsIt->begin()),
         proposalsIt->size() / 8});
    auto signedMessage = signedMessageReader.getRoot<proto::SignedMessage>();
    capnp::FlatArrayMessageReader proposalBodyReader(
        {reinterpret_cast<const capnp::word *>(signedMessage.getBody().begin()),
         signedMessage.getBody().size() / 8});
    auto proposalBody = proposalBodyReader.getRoot<proto::ProposalBody>();
    for (const auto &req : proposalBody.getRequests()) {
      responseToClient(req, newAcceptedProposal.proposalHash);
    }
    proposalsIt++;
    acksIt++;
  }
  while (proposalsIt != proposalsEnd) {
    auto &newPendingProposal = pendingChain.emplace_back();
    newPendingProposal.proposal.assign(proposalsIt->begin(),
                                       proposalsIt->end());
    SHA256(newPendingProposal.proposal.data(),
           newPendingProposal.proposal.size(), newPendingProposal.proposalHash);
    capnp::FlatArrayMessageReader signedMessageReader(
        {reinterpret_cast<const capnp::word *>(proposalsIt->begin()),
         proposalsIt->size() / 8});
    auto signedMessage = signedMessageReader.getRoot<proto::SignedMessage>();
    capnp::FlatArrayMessageReader proposalBodyReader(
        {reinterpret_cast<const capnp::word *>(signedMessage.getBody().begin()),
         signedMessage.getBody().size() / 8});
    auto proposalBody = proposalBodyReader.getRoot<proto::ProposalBody>();
    for (const auto &req : proposalBody.getRequests()) {
      responseToClient(req, newPendingProposal.proposalHash);
    }
    auto cancelers = getProposalCancelers(newPendingProposal.proposalHash);
    if (!cancelers.contains(idx)) {
      uint8_t compressedSig[64];
      signData(newPendingProposal.proposalHash, compressedSig);
      capnp::MallocMessageBuilder ackBuilder;
      auto ack = ackBuilder.initRoot<proto::Acknowledgement>();
      ack.setProposalHash({newPendingProposal.proposalHash, 32});
      ack.getSign().setSign({compressedSig, 64});
      ack.getSign().setIdx(idx);
      sendToNode(signedMessage.getSign().getIdx(), MessageType::PROPOSAL_ACK,
                 ackBuilder);
      for (const auto &nodeIdx : cancelers) {
        sendToNode(nodeIdx, MessageType::PROPOSAL_ACK, ackBuilder);
      }
    }
    proposalsIt++;
  }
}

void ZyzaReplica::sendFallbackAlert(uint16_t nodeIdx) {
  capnp::MallocMessageBuilder fallbackAlertBodyBuilder;
  auto fallbackAlertBody =
      fallbackAlertBodyBuilder.initRoot<proto::FallbackAlertBody>();
  fallbackAlertBody.setLastAckedProposalHash(
      {acceptedChain.back().proposalHash, 32});
  auto unackedProposals =
      fallbackAlertBody.initUnackedSignedProposals(pendingChain.size());
  int totalRequests = 0;
  int i = 0;
  for (const auto &pendingProposal : pendingChain) {
    unackedProposals.set(
        i, {pendingProposal.proposal.data(), pendingProposal.proposal.size()});
    i++;
    capnp::FlatArrayMessageReader proposalSignedMessageReader(
        {reinterpret_cast<const capnp::word *>(pendingProposal.proposal.data()),
         pendingProposal.proposal.size() / sizeof(capnp::word)});
    auto proposalSignedMessage =
        proposalSignedMessageReader.getRoot<proto::SignedMessage>();
    capnp::FlatArrayMessageReader bodyMessage(
        {reinterpret_cast<const capnp::word *>(
             proposalSignedMessage.getBody().begin()),
         proposalSignedMessage.getBody().size() / 8});
    auto body = bodyMessage.getRoot<proto::ProposalBody>();
    totalRequests += body.getRequests().size();
  }
  auto cancelSigns =
      fallbackAlertBody.initUnackedSignedProposals(totalRequests);
  i = 0;
  for (const auto &pendingProposal : pendingChain) {
    capnp::FlatArrayMessageReader proposalSignedMessageReader(
        {reinterpret_cast<const capnp::word *>(pendingProposal.proposal.data()),
         pendingProposal.proposal.size() / sizeof(capnp::word)});
    auto proposalSignedMessage =
        proposalSignedMessageReader.getRoot<proto::SignedMessage>();
    capnp::FlatArrayMessageReader bodyMessage(
        {reinterpret_cast<const capnp::word *>(
             proposalSignedMessage.getBody().begin()),
         proposalSignedMessage.getBody().size() / 8});
    auto body = bodyMessage.getRoot<proto::ProposalBody>();
    for (const auto &req : body.getRequests()) {
      uint8_t cancelProof[8 + 32];
      *reinterpret_cast<uint64_t *>(cancelProof) = req.getId();
      memcpy(cancelProof + 8, pendingProposal.proposalHash, 32);
      uint8_t cancelHash[32];
      SHA256(cancelProof, 8 + 32, cancelHash);
      uint8_t cancelSign[64];
      signData(cancelHash, cancelSign);
      cancelSigns.set(i, {cancelSign, 64});
      i++;
    }
  }
  capnp::MallocMessageBuilder signedMessage;
  createSignedMessage(fallbackAlertBodyBuilder, signedMessage);
  sendToNode(nodeIdx, MessageType::FALLBACK_ALERT, signedMessage);
}

void ZyzaReplica::handleTimeout() {
  std::clog << idx << ": switching to fallback" << std::endl;
  uint16_t backupLeader = (currentFastPathLeader + 1) % nodesCount;

  if (backupLeader == idx) {
    currentBackupPathLeader = idx;
    transitionToLeaderFallbackPath();
  } else {
    currentBackupPathLeader = currentFastPathLeader;
    transitionToNextBackupLeader();
  }
}

void ZyzaReplica::sendToClient(const std::string &dstIp, uint16_t dstPort,
                               MessageType messageType,
                               capnp::MessageBuilder &message) {
  uint64_t msgId = 0;
  auto rc = getrandom(&msgId, sizeof(msgId), 0);
  assert(rc == sizeof(msgId));
  uint32_t size =
      capnp::computeSerializedSizeInWords(message) * 8 + sizeof(MessageHeader);
  auto data = std::make_unique<uint8_t[]>(size);
  new (data.get()) MessageHeader(size, static_cast<uint16_t>(idx),
                                 static_cast<uint16_t>(messageType), msgId);
  kj::ArrayOutputStream aos(
      {data.get() + sizeof(MessageHeader), size - sizeof(MessageHeader)});
  capnp::writeMessage(aos, message);
  ns3::Address sinkAddress(ns3::InetSocketAddress(dstIp.c_str(), dstPort));
  std::clog << ns3::Simulator::Now().As() << ": " << idx << ": sending message "
            << messageTypeToString(messageType) << " to client" << std::endl;
  serverUdpSocket->SendTo(data.get(), size, 0, sinkAddress);
}

void ZyzaReplica::sendToNode(int node, MessageType messageType,
                             capnp::MessageBuilder &message) {
  NS_LOG_DEBUG(idx << " " << ns3::Simulator::Now().As(ns3::Time::S)
                   << " sending message " << messageTypeToString(messageType)
                   << " to " << node);
  auto h = activeNodeConnections[node];
  uint32_t size =
      capnp::computeSerializedSizeInWords(message) * 8 + sizeof(MessageHeader);
  auto data = std::make_unique<char[]>(size);
  uint64_t msgId = 0;
  auto rc = getrandom(&msgId, sizeof(msgId), 0);
  assert(rc == sizeof(msgId));
  auto *header =
      new (data.get()) MessageHeader(size, static_cast<uint16_t>(idx),
                                     static_cast<uint16_t>(messageType), msgId);
  kj::ArrayOutputStream aos(
      {reinterpret_cast<uint8_t *>(data.get() + sizeof(MessageHeader)),
       size - sizeof(MessageHeader)});
  capnp::writeMessage(aos, message);
  if (h != nullptr) {
    std::clog << ns3::Simulator::Now().As() << ": " << idx << ": sending "
              << messageTypeToString(messageType) << " to " << node
              << " msgId: " << std::hex << header->msgId << std::dec
              << std::endl;
    //        hexdump(data.get(), size);
    h->Send(reinterpret_cast<const uint8_t *>(data.get()), size, 0);
  } else {
    std::clog << ns3::Simulator::Now().As() << ": " << idx
              << ": adding pending message " << messageTypeToString(messageType)
              << " to " << node << " msgId: " << std::hex << header->msgId
              << std::dec << std::endl;
    //        hexdump(data.get(), size);
    pendingNodeMessages[node].emplace_back(std::move(data), size);
  }
}

void ZyzaReplica::restartConnectionToNode(int i) {
  NS_LOG_INFO(idx << " " << ns3::Simulator::Now().As(ns3::Time::S)
                  << " restart connection to " << i);
  auto con = ns3::Socket::CreateSocket(p2psh.GetSpokeNode(idx),
                                       ns3::TcpSocketFactory::GetTypeId());
  con->Bind();
  ns3::Address sinkAddress(
      ns3::InetSocketAddress(p2psh.GetSpokeIpv4Address(i), 1234));
  con->SetConnectCallback(
      [this, i](ns3::Ptr<ns3::Socket> con) {
        NS_LOG_INFO(idx << " " << ns3::Simulator::Now().As(ns3::Time::S)
                        << " connected to " << i);
        activeNodeConnections[i] = con;
        sendPendingNodeMessages(i);
      },
      [this, i](auto) -> void {
        NS_LOG_ERROR(idx << " " << ns3::Simulator::Now().As(ns3::Time::MS)
                         << " failed to connect to " << i);
      });
  if (activeNodeConnections[i] != nullptr) {
    activeNodeConnections[i]->Close();
    activeNodeConnections[i] = nullptr;
  }
  con->Connect(sinkAddress);
}

void ZyzaReplica::sendPendingNodeMessages(int i) {
  auto h = activeNodeConnections[i];
  if (pendingNodeMessages.contains(i)) {
    for (auto &item : pendingNodeMessages[i]) {
      auto *header = reinterpret_cast<const MessageHeader *>(item.first.get());
      std::clog << ns3::Simulator::Now().As() << ": " << idx
                << ": sending pending message "
                << messageTypeToString(
                       static_cast<MessageType>(header->messageType))
                << " to " << i << " msgId: " << std::hex << header->msgId
                << std::dec << std::endl;
      h->Send(reinterpret_cast<const uint8_t *>(item.first.get()), item.second,
              0);
    }
    pendingNodeMessages.erase(i);
  }
}

void ZyzaReplica::createSignedMessage(capnp::MallocMessageBuilder &body,
                                      capnp::MallocMessageBuilder &message) {
  auto serializedBody = capnp::messageToFlatArray(body);
  auto signedMessage = message.initRoot<proto::SignedMessage>();
  signedMessage.setBody(serializedBody.asBytes());
  auto signBuilder = signedMessage.initSign();
  signBuilder.setIdx(idx);
  auto sign = signBuilder.initSign(64);
  signData(serializedBody.asBytes().begin(), serializedBody.asBytes().size(),
           sign.begin());
}

bool ZyzaReplica::validateAckList(
    const uint8_t *proposalHash,
    const capnp::List<proto::Signature>::Reader ackList) {

  if (ackList.size() != quorumSize) {
    std::clog << "wrong ack list size" << std::endl;
    return false;
  }
  std::map<uint16_t, uint8_t[64]> signatures;
  for (const auto &sign : ackList) {
    if (sign.getSign().size() != 64) {
      std::clog << "wrong ack signature size" << std::endl;
      return false;
    }
    if (!verifyData(proposalHash, sign.getSign().begin(), sign.getIdx())) {
      std::clog << "wrong signature" << std::endl;
      return false;
    }
    memcpy(signatures[sign.getIdx()], sign.getSign().begin(), 64);
  }
  if (signatures.size() != quorumSize) {
    std::clog << "duplicated acks in ack list" << std::endl;
    return false;
  }
  for (const auto &canceler : getProposalCancelers(proposalHash)) {
    if (!signatures.contains(canceler)) {
      std::clog << "ack list does not contain ack from canceler" << std::endl;
      return false;
    }
  }
  return true;
}

bool ZyzaReplica::validateResendChainResponse(
    const proto::ResendChainResponse::Reader &nsr) {
  if (nsr.getProposals().size() <= nsr.getAcknowledgements().size() ||
      nsr.getProposals().size() >
          nsr.getAcknowledgements().size() + maxPendingChainLength) {
    std::clog << "wrong size of chain" << std::endl;
    return false;
  }
  auto proposalsIt = nsr.getProposals().begin();
  auto proposalsEnd = nsr.getProposals().end();
  auto acksIt = nsr.getAcknowledgements().begin();
  auto acksEnd = nsr.getAcknowledgements().end();
  int lastSigner;
  {
    capnp::FlatArrayMessageReader reader(
        {reinterpret_cast<const capnp::word *>(
             acceptedChain.back().proposal.data()),
         acceptedChain.back().proposal.size() / 8});
    lastSigner = reader.getRoot<proto::SignedMessage>().getSign().getIdx();
  }
  uint8_t prevProposalHash[32];
  memcpy(prevProposalHash, acceptedChain.back().proposalHash, 32);
  while (proposalsIt != proposalsEnd) {
    capnp::FlatArrayMessageReader reader(
        {reinterpret_cast<const capnp::word *>(proposalsIt->begin()),
         proposalsIt->size() / 8});
    auto signedMessage = reader.getRoot<proto::SignedMessage>();
    int expectedLeader = acksIt == acksEnd ? lastSigner : -1;
    int expectedIndex =
        acceptedChain.size() + (proposalsIt - nsr.getProposals().begin());
    if (!validateProposal(signedMessage, acceptedChain.back().proposalHash,
                          expectedLeader, expectedIndex)) {
      return false;
    }
    SHA256(signedMessage.getBody().begin(), signedMessage.getBody().size(),
           prevProposalHash);
    if (acksIt != acksEnd && !validateAckList(prevProposalHash, *acksIt)) {
      return false;
    }
    lastSigner = reader.getRoot<proto::SignedMessage>().getSign().getIdx();
    proposalsIt++;
    acksIt++;
  }
  return true;
}

void ZyzaReplica::signData(const uint8_t *data, size_t size, uint8_t *result) {
  uint8_t hash[32];
  SHA256(data, size, hash);
  signData(hash, result);
}

void ZyzaReplica::signData(const uint8_t *hash, uint8_t *result) {
  secp256k1_ecdsa_signature sig;
  int rc = secp256k1_ecdsa_sign(secpCtx, &sig, hash, seckey, nullptr, nullptr);
  assert(rc == 1);
  rc = secp256k1_ecdsa_signature_serialize_compact(secpCtx, result, &sig);
  assert(rc == 1);
}
} // namespace zyza
