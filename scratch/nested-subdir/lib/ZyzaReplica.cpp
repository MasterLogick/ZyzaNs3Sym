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
    int nodesCount, int idx, ns3::PointToPointStarHelper &p2psh,
    std::vector<std::vector<uint8_t>> &serializedPublicKeys,
    std::span<const uint8_t> privateKey,
    std::chrono::milliseconds fallbackTimeout)
    : Endpoint(p2psh.GetSpokeNode(idx)),
      ZyzaCommon(nodesCount, serializedPublicKeys), idx(idx),
      alertTimeout(fallbackTimeout), currentFastPathLeader(0),
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
  case MessageType::NEW_PROPOSAL:
    processProposal(reader.getRoot<proto::SignedMessage>(), true);
    break;
  case MessageType::PROPOSAL_ACK:
    processAcknowledgement(reader.getRoot<proto::Acknowledgement>());
    break;
  case MessageType::PROPOSAL_KEEP_REQUEST:
    processProposalKeepRequest(reader.getRoot<proto::Acknowledgement>());
    break;
  case MessageType::FALLBACK_ALERT:
    processFallbackAlert(reader.getRoot<proto::SignedMessage>());
    break;
  case MessageType::PROPOSAL_STATUS_REQUEST:
    processProposalStatusRequest(
        reader.getRoot<proto::ProposalStatusRequest>());
    break;
  case MessageType::PROPOSAL_STATUS_RESPONSE:
    processProposalStatusResponse(reader.getRoot<proto::SignedMessage>());
    break;
  case MessageType::RECOVERY:
    processRecovery(reader.getRoot<proto::Recovery>());
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
  default:
    break;
  }
}

void ZyzaReplica::processRequest(const proto::Request::Reader &request) {
  if (currentState == ReplicaState::LEADER_FAST) {
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

void ZyzaReplica::processProposal(const proto::SignedMessage::Reader &proposal,
                                  bool checkSigner) {
  if (currentState != ReplicaState::BACKUP_FAST) {
    return;
  }
  int expectedSigner;
  if (checkSigner) {
    if (initPassed) {
      expectedSigner = currentFastPathLeader;
    } else {
      expectedSigner = 0;
    }
  } else {
    expectedSigner = -1;
  }
  if (!validateProposal(proposal, pendingChain.back().first, expectedSigner,
                        initPassed, proposalOrd,
                        maxPendingChainLength == pendingChain.size(),
                        pendingChain)) {
    return;
  }
  capnp::FlatArrayMessageReader bodyMessage(
      {reinterpret_cast<const capnp::word *>(proposal.getBody().begin()),
       proposal.getBody().size() / 8});
  auto body = bodyMessage.getRoot<proto::ProposalBody>();
  std::clog << idx << ": got valid proposal with ord " << body.getOrd()
            << std::endl;
  if (initPassed) {
    for (const auto &item : body.getAcknowledgements()) {
      auto &d = acceptedChain.emplace_back();
      auto &s = pendingChain.front();
      memcpy(d.first, s.first, 32);
      d.second.setRoot(s.second.getRoot<proto::SignedMessage>().asReader());
      pendingChain.pop_front();
    }
  }
  uint8_t newProposalHash[32];
  SHA256(proposal.getBody().asBytes().begin(),
         proposal.getBody().asBytes().size(), newProposalHash);
  //  hexdump(proposalHash, "received proposal body hash");
  {
    auto &pendingBlock = pendingChain.emplace_back();
    memcpy(pendingBlock.first, newProposalHash, 32);
    pendingBlock.second.setRoot(proposal);
  }
  for (const auto &item : body.getRequests()) {
    responseToClient(item, newProposalHash);
  }
  uint8_t compressedSig[64];
  signData(newProposalHash, compressedSig);
  capnp::MallocMessageBuilder ackBuilder;
  auto ack = ackBuilder.initRoot<proto::Acknowledgement>();
  ack.setHash({newProposalHash, 32});
  ack.getSign().setSign({compressedSig, 64});
  ack.getSign().setIdx(idx);
  sendToNode(currentFastPathLeader, MessageType::PROPOSAL_ACK, ackBuilder);
  for (const auto &nodeIdx : getProposalKeepers(newProposalHash)) {
    sendToNode(nodeIdx, MessageType::PROPOSAL_KEEP_REQUEST, ackBuilder);
  }
  backupFastPathTimeout.Cancel();
  backupFastPathTimeout = ns3::Simulator::Schedule(
      ns3::Time::From(alertTimeout.count(), ns3::Time::MS),
      [this] { handleBackupFastPathTimeout(); });
  initPassed = true;
  proposalOrd++;
  std::clog << "processed proposal" << std::endl;
}

void ZyzaReplica::processAcknowledgement(
    const proto::Acknowledgement::Reader &reader) {
  if (currentState != ReplicaState::LEADER_FAST) {
    return;
  }
  if (reader.getHash().size() != 32) {
    std::clog << "wrong ack proposal hash size" << std::endl;
    return;
  }
  if (reader.getSign().getSign().size() != 64) {
    std::clog << "wrong ack proposal sign size" << std::endl;
    return;
  }
  bool validSign = validateData(
      std::span<const uint8_t, 32>{reader.getHash().begin(), 64},
      std::span<const uint8_t, 64>{reader.getSign().getSign().begin(), 64},
      reader.getSign().getIdx());
  if (!validSign) {
    std::clog << "wrong ack proposal sign" << std::endl;
    return;
  }
  for (auto &item : pendingProposals) {
    if (memcmp(item.blockHash, reader.getHash().begin(), 32) != 0) {
      continue;
    }
    if (item.acks.size() == quorumSize) {
      return;
    }
    memcpy(item.acks[reader.getSign().getIdx()],
           reader.getSign().getSign().begin(), 64);
    std::clog << "processed ack" << std::endl;
    break;
  }
  if (pendingProposals.begin()->acks.size() == quorumSize) {
    onPendingBlockAcksReady();
  }
  hexdump(reader.getHash().begin(), "unknown ack proposal hash");
}

void ZyzaReplica::processProposalKeepRequest(
    const proto::Acknowledgement::Reader &proposalKeepRequest) {
  if (proposalKeepRequest.getHash().size() != 32) {
    std::clog << "wrong ack proposal hash size" << std::endl;
    return;
  }
  if (proposalKeepRequest.getSign().getSign().size() != 64) {
    std::clog << "wrong ack proposal sign size" << std::endl;
    return;
  }
  if (!validateData(
          std::span<const uint8_t, 32>{proposalKeepRequest.getHash().begin(),
                                       32},
          std::span<const uint8_t, 64>{
              proposalKeepRequest.getSign().getSign().begin(), 64},
          proposalKeepRequest.getSign().getIdx())) {
    return;
  }
  keptProposalAcks
      .emplace_back(std::make_unique<capnp::MallocMessageBuilder>())
      ->setRoot(proposalKeepRequest);
}

void ZyzaReplica::processFallbackAlert(
    const proto::SignedMessage::Reader &fallbackAlert) {
  if (currentState != ReplicaState::LEADER_FALLBACK) {
    return;
  }
  capnp::FlatArrayMessageReader unackedProposalBodyReader(
      {reinterpret_cast<const capnp::word *>(
           fallbackAlert.getUnackedProposal().begin()),
       fallbackAlert.getUnackedProposal().size() / 8});
  auto proposal = unackedProposalBodyReader.getRoot<proto::Proposal>();
  auto myUnackedProposal =
      pendingChain.front().second.getRoot<proto::Proposal>();
  if (!validateProposal(proposal, acceptedChain.back().first,
                        myUnackedProposal.getSign().getIdx(), true,
                        currentFastPathLeader, )) {
    return;
  }
  uint8_t hash[32];
  SHA256(fallbackAlert.getUnackedProposal().begin(),
         fallbackAlert.getUnackedProposal().size(), hash);
  secp256k1_ecdsa_signature sig;
  int rc = secp256k1_ecdsa_signature_parse_compact(
      secpCtx, &sig, fallbackAlert.getSign().getSign().begin());
  if (!rc) {
    std::clog << "wrong fallback alert packed sign" << std::endl;
    return;
  }
  rc = secp256k1_ecdsa_verify(secpCtx, &sig, hash,
                              &publicKeys[fallbackAlert.getSign().getIdx()]);
  if (!rc) {
    std::clog << "wrong fallback alert sign" << std::endl;
    return;
  }
  std::unique_ptr<capnp::MallocMessageBuilder> mb(
      new capnp::MallocMessageBuilder());
  mb->setRoot(fallbackAlert);
  acceptedFallbackAlerts[fallbackAlert.getSign().getIdx()] = std::move(mb);
  std::clog << "accepted fallback alert" << std::endl;
  if (acceptedFallbackAlerts.size() == quorumSize) {
    std::clog << "approved force switching to fallback" << std::endl;
    sendDropRequests();
  }
}

void ZyzaReplica::processProposalStatusRequest(
    const proto::ProposalStatusRequest::Reader &proposalStatusRequest) {
  if (proposalStatusRequest.getProposalHash().size() != 32) {
    std::clog << "wrong proposal status request hash size" << std::endl;
    return;
  }
  if (proposalStatusRequest.getIdx() >= nodesCount) {
    std::clog << "wrong proposal status request idx" << std::endl;
    return;
  }
  std::map<uint16_t, uint8_t[64]> signatures;
  for (const auto &item : keptProposalAcks) {
    auto reader = item->getRoot<proto::Acknowledgement>();
    if (memcmp(reader.getHash().begin(),
               proposalStatusRequest.getProposalHash().begin(), 32) == 0) {
      memcpy(signatures[reader.getSign().getIdx()],
             reader.getSign().getSign().begin(), 64);
    }
    if (signatures.size() == quorumSize) {
      break;
    }
  }
  capnp::MallocMessageBuilder proposalStatusResponseBodyBuilder;
  auto proposalStatusResponseBody =
      proposalStatusResponseBodyBuilder
          .initRoot<proto::ProposalStatusResponseBody>();
  proposalStatusResponseBody.setProposalHash(
      proposalStatusRequest.getProposalHash());
  if (signatures.size() == quorumSize) {
    auto acks = proposalStatusResponseBody.initAcks(quorumSize);
    int i = 0;
    for (const auto &[nodeIdx, sign] : signatures) {
      acks[i].setIdx(nodeIdx);
      acks[i].setSign({sign, 64});
      i++;
    }
  } else {
    proposalStatusResponseBody.setNotEnoughAcks(0);
  }
  capnp::MallocMessageBuilder responseBuilder;
  createSignedMessage(proposalStatusResponseBodyBuilder, responseBuilder);
  sendToNode(proposalStatusRequest.getIdx(),
             MessageType::PROPOSAL_STATUS_RESPONSE, responseBuilder);
}

void ZyzaReplica::processProposalStatusResponse(
    const proto::SignedMessage::Reader &proposalStatusRequest) {
  if (currentState != ReplicaState::LEADER_FALLBACK) {
    return;
  }
  -- -- -;
}

void ZyzaReplica::processRecovery(const proto::Recovery::Reader &recovery) {
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
    if (!validateData(item.getUnackedProposal(), item.getSign())) {
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
  if (nsr.getLastAckedProposal().size() != 32) {
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
  if (memcmp(zeroHash, nsr.getLastAckedProposal().begin(), 32) == 0) {
    resendChainPart(acceptedChain.begin(), nsr.getIdx(), acceptedChain.size());
    return;
  } else {
    if (currentState == ReplicaState::LEADER_FAST) {
      int acceptedChainPartSize = 0;
      auto iter = pendingProposals.end();
      while (iter != pendingProposals.begin()) {
        iter--;
        acceptedChainPartSize++;
        if (memcmp(iter->blockHash, nsr.getLastAckedProposal().begin(), 32) ==
            0) {
          resendChainPart(acceptedChain.end(), nsr.getIdx(),
                          acceptedChainPartSize);
          return;
        }
      }
    } else {
      int acceptedChainPartSize = 0;
      auto iter = pendingChain.end();
      while (iter != pendingChain.begin()) {
        iter--;
        acceptedChainPartSize++;

        if (memcmp(iter->first, nsr.getLastAckedProposal().begin(), 32) == 0) {
          resendChainPart(acceptedChain.end(), nsr.getIdx(),
                          acceptedChainPartSize);
          return;
        }
      }
    }
    int acceptedChainPartSize = 0;
    auto iter = acceptedChain.end();
    while (iter != acceptedChain.begin()) {
      iter--;
      acceptedChainPartSize++;

      if (memcmp(iter->first, nsr.getLastAckedProposal().begin(), 32) == 0) {
        resendChainPart(iter, nsr.getIdx(), acceptedChainPartSize);
        return;
      }
    }
    resendChainPart(acceptedChain.end(), nsr.getIdx(), 0);
  }
}

void ZyzaReplica::processResendChainResponse(
    const proto::ResendChainResponse::Reader &nsr) {
  if (currentState != ReplicaState::BACKUP_FALLBACK) {
    return;
  }
  auto chainPart = nsr.getChainPart();
  if (chainPart.size() == 0) {
    return;
  }
  if (acceptedChain.empty() && chainPart.size() == 1) {
    return;
  }
  auto it = chainPart.begin();
  uint8_t zeroHash[32];
  memset(zeroHash, 0, 32);
  bool oldInitPassed = initPassed;
  while (it != chainPart.end()) {
    const uint8_t *expectedPrevHash =
        initPassed ? pendingChain.back().first : zeroHash;
    if (validateProposal(*it, expectedPrevHash, -1, initPassed, -1,
                         pendingChain.size() == maxPendingChainLength,
                         pendingChain)) {
      break;
    }
    it++;
  }
  if (it == chainPart.end()) {
    return;
  }
  while (it != chainPart.end()) {
    processProposal(*it, false);
  }
}

void ZyzaReplica::transitionToNextBackupLeader() {}

void ZyzaReplica::transitionToLeaderFallback() {
  if (currentState == ReplicaState::BACKUP_FAST) {
    backupFastPathTimeout.Cancel();
  } else if (currentState == ReplicaState::BACKUP_FALLBACK) {
    recoveryMessageBuilder = nullptr;
    recoveryAcks.clear();
  }
  currentState = ReplicaState::LEADER_FALLBACK;

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
  std::clog << "starting a new round" << std::endl;
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
  capnp::MallocMessageBuilder proposalBodyBuilder;
  auto proposalBody = proposalBodyBuilder.initRoot<proto::ProposalBody>();
  proposalBody.setPrevProposalHash({pendingProposals.back().blockHash, 32});
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
      proposalBody.initAcknowledgements(acceptedProposals);
    }
    it = pendingProposals.begin();
    for (int i = 0; i < acceptedProposals; ++i) {
      auto d = proposalBody.getAcknowledgements().init(i, quorumSize);
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
      auto &newBlock = acceptedChain.emplace_back();
      memcpy(newBlock.first, pendingProposals.begin()->blockHash, 32);
      newBlock.second.setRoot(pendingProposals.begin()
                                  ->proposal.getRoot<proto::SignedMessage>()
                                  .asReader());
      initPassed = true;
    }
  }
  proposalBody.initRequests(pendingRequests.size());
  for (int i = 0; i < pendingRequests.size(); ++i) {
    proposalBody.getRequests().setWithCaveats(
        i, pendingRequests[i]->getRoot<proto::Request>());
  }
  proposalBody.setOrd(proposalOrd);
  proposalOrd++;

  auto newPendingProposal = pendingProposals.emplace({});
  createSignedMessage(proposalBodyBuilder, newPendingProposal->proposal);
  auto signedProposal =
      newPendingProposal->proposal.getRoot<proto::SignedMessage>();
  SHA256(signedProposal.getBody().asBytes().begin(),
         signedProposal.getBody().asBytes().size(),
         newPendingProposal->blockHash);
  hexdump(newPendingProposal->blockHash, "new round proposal body hash");
  signData(newPendingProposal->blockHash, newPendingProposal->acks[idx]);

  for (const auto &pendingRequest : pendingRequests) {
    responseToClient(pendingRequest->getRoot<proto::Request>(),
                     newPendingProposal->blockHash);
  }
  pendingRequests.clear();

  for (int i = 0; i < nodesCount; ++i) {
    if (i == idx) {
      continue;
    }
    sendToNode(i, MessageType::NEW_PROPOSAL, newPendingProposal->proposal);
  }

  capnp::MallocMessageBuilder ackBuilder;
  auto ack = ackBuilder.initRoot<proto::Acknowledgement>();
  ack.setHash({newPendingProposal->blockHash, 32});
  auto ackSign = ack.initSign();
  ackSign.setIdx(idx);
  ackSign.setSign({newPendingProposal->acks[idx], 64});
  for (const auto &keeperIdx :
       getProposalKeepers(newPendingProposal->blockHash)) {
    sendToNode(keeperIdx, MessageType::PROPOSAL_KEEP_REQUEST, ackBuilder);
  }
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
    std::list<std::pair<uint8_t[32], capnp::MallocMessageBuilder>>::iterator
        acceptedChainIter,
    int node, int acceptedChainPartSize) {
  capnp::MallocMessageBuilder resendChainResponseBuilder;
  auto resendChainResponse =
      resendChainResponseBuilder.initRoot<proto::ResendChainResponse>();
  int pendingChainSize;
  if (currentState == ReplicaState::LEADER_FAST) {
    pendingChainSize = pendingProposals.size();
  } else {
    pendingChainSize = pendingChain.size();
  }
  auto chainPart = resendChainResponse.initChainPart(acceptedChainPartSize +
                                                     pendingChainSize);
  int i = 0;
  while (acceptedChainIter != acceptedChain.end()) {
    chainPart.setWithCaveats(
        i, acceptedChainIter->second.getRoot<proto::SignedMessage>());
    i++;
    acceptedChainIter++;
  }
  if (currentState == ReplicaState::LEADER_FAST) {
    for (auto &item : pendingProposals) {
      chainPart.setWithCaveats(i,
                               item.proposal.getRoot<proto::SignedMessage>());
      i++;
    }
  } else {
    for (auto &item : pendingChain) {
      chainPart.setWithCaveats(i, item.second.getRoot<proto::SignedMessage>());
      i++;
    }
  }
  sendToNode(node, MessageType::RESEND_CHAIN_RESPONSE,
             resendChainResponseBuilder);
}

void ZyzaReplica::handleBackupFastPathTimeout() {
  std::clog << idx << ": switching to fallback" << std::endl;
  uint16_t backupLeader = (currentFastPathLeader + 1) % nodesCount;

  if (backupLeader == idx) {
    currentBackupPathLeader = idx;
    transitionToLeaderFallback();
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

std::vector<uint16_t>
ZyzaReplica::getProposalKeepers(std::span<uint8_t, 32> hash) {
  std::vector<uint16_t> keepers(keepersPerProposal);
  uint8_t h[2][32];
  memcpy(h[0], hash.data(), 32);
  for (int i = 0; i < keepersPerProposal; ++i) {
    uint8_t *src = h[i % 2];
    uint8_t *dst = h[(i + 1) % 2];
    SHA256(src, 32, dst);
    keepers[i] = ((dst[1] << 8) | dst[0]) % nodesCount;
  }
  return std::move(keepers);
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
