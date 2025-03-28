#include "ZyzaReplica.h"

#include "ns3/core-module.h"

#include <capnp/message.h>
#include <capnp/serialize-packed.h>
#include <capnp/serialize.h>
#include <cassert>
#include <iostream>
#include <openssl/sha.h>
#include <secp256k1.h>
#include <thread>

namespace zyza {
NS_LOG_COMPONENT_DEFINE("ZyzaReplica");

ZyzaReplica::ZyzaReplica(
    int nodesCount, int idx, ns3::PointToPointStarHelper &p2psh,
    std::vector<std::vector<uint8_t>> &serializedPublicKeys,
    std::span<const uint8_t> privateKey, std::chrono::milliseconds alertTimeout,
    std::chrono::milliseconds leaderSwitchTimeout, int maxPendingChainLength)
    : Endpoint(p2psh.GetSpokeNode(idx)),
      ZyzaCommon(nodesCount, serializedPublicKeys), idx(idx),
      alertTimeout(alertTimeout), currentFastPathLeader(0),
      currentBackupPathLeader(0), initPassed(false), backupFastPathTimeout(),
      p2psh(p2psh), sentClientResponses(false),
      leaderSwitchTimeout(leaderSwitchTimeout),
      maxPendingChainLength(maxPendingChainLength), hasRecoveryState(false) {
  assert(privateKey.size() == 32);
  memcpy(seckey, privateKey.data(), 32);
  assert(secp256k1_ec_seckey_verify(secp256k1_context_static, seckey));
  activeNodeConnections.resize(nodesCount);
  if (idx == 0) {
    startupLeader();
  } else {
    startupBackup();
  }
}

void ZyzaReplica::StartApplication() { Endpoint::run(); }

void ZyzaReplica::StopApplication() {
  backupFastPathTimeout.Cancel();
  nextLeaderAlertTimerEvent.Cancel();
  for (const auto &item : activeNodeConnections) {
    item->Close();
    item->Dispose();
  }
  Endpoint::stop();
}

void ZyzaReplica::startupLeader() {
  currentState = ReplicaState::LEADER_FAST;
  currentFastPathLeader = 0;
  initPassed = false;

  capnp::MallocMessageBuilder proposalBuilder;
  auto proposal = proposalBuilder.initRoot<proto::Proposal>();
  auto proposalBody = proposal.getSignedProposal().getBody();
  uint8_t zeroHash[32] = {0};
  proposalBody.setPrevProposalHash({zeroHash, 32});
  proposalBody.initRequests(0);
  proposalBody.setOrd(0);
  signMessage(proposal.getSignedProposal().asGeneric());
  uint8_t proposalHash[32];
  hashStruct(proposal.getSignedProposal().asReader(), proposalHash);
  hexdump(proposalHash, "new round proposal hash");

  proposal.initAcknowledgements2(0);
  for (int i = 0; i < nodesCount; ++i) {
    sendToNode(i, MessageType::PROPOSAL, proposalBuilder);
  }
  auto &newPendingProposal = pendingChain.emplace_back();
  memcpy(newPendingProposal.proposalHash, proposalHash, 32);
  newPendingProposal.proposal.setTypedRoot(proposal.getSignedProposal());
  signData(proposalHash, newPendingProposal.acks1[idx]);

  backupFastPathTimeout.Cancel();
  backupFastPathTimeout = ns3::Simulator::Schedule(
      ns3::Time::From(alertTimeout.count(), ns3::Time::MS),
      [this] { handleTimeout(); });
}

void ZyzaReplica::startupBackup() { currentState = ReplicaState::BACKUP_FAST; }

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
            << header->senderIdx << " of size " << message.size()
            << " msgId: " << std::hex << header->msgId << std::dec << std::endl;
  kj::ArrayInputStream ais({content.data(), content.size()});
  capnp::PackedMessageReader reader(ais);
  switch (messageType) {
  case MessageType::PROPOSAL:
    processProposal(reader.getRoot<proto::Proposal>());
    break;
  case MessageType::PROPOSAL_ACK_1:
    processAcknowledgement1(reader.getRoot<proto::Acknowledgement>());
    break;
  case MessageType::PROPOSAL_ACK_2:
    processAcknowledgement2(reader.getRoot<proto::Acknowledgement>());
    break;
  case MessageType::FALLBACK_ALERT:
    processFallbackAlert(
        reader.getRoot<proto::SignedMessage<proto::FallbackAlertBody>>());
    break;
  case MessageType::RECOVERY_STATE:
    processRecoveryState(
        reader.getRoot<proto::SignedMessage<proto::RecoveryStateBody>>());
    break;
  case MessageType::CLIENT_RESPONSE:
    processClientResponse(reader.getRoot<proto::ClientResponse>());
    break;
  case MessageType::CLIENT_RESPONSES:
    processClientResponses(
        reader.getRoot<proto::SignedMessage<proto::ClientResponsesBody>>());
    break;
  case MessageType::RECOVERY:
    processRecovery(
        reader.getRoot<proto::SignedMessage<proto::RecoveryBody>>());
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
            << header->senderIdx << " of size " << message.size()
            << " msgId: " << std::hex << header->msgId << std::dec << std::endl;
  kj::ArrayInputStream ais({content.data(), content.size()});
  capnp::PackedMessageReader reader(ais);
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
      if (req.getTyped().getId() == request.getId()) {
        std::clog << "got request with existing id" << std::endl;
        return;
      }
    }
    pendingRequests.emplace_back().setTypedRoot(request);
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
  if (clientResponses.contains(reader.getId())) {
    std::clog << "already got client response" << std::endl;
    return;
  }
  if (!validateClientResponse(reader)) {
    return;
  }
  clientResponses[reader.getId()].setTypedRoot(reader);
  onClientResponse();
}

void ZyzaReplica::processClientResponses(
    const proto::SignedMessage<proto::ClientResponsesBody>::Reader &reader) {
  if (currentState != ReplicaState::LEADER_FALLBACK) {
    return;
  }
  if (acceptedFallbackAlerts.size() != quorumSize) {
    return;
  }
  if (backupNodesClientResponses.contains(reader.getSign().getIdx())) {
    std::clog << "already got client responses from node" << std::endl;
  }
  if (!verifySignedMessage(reader.asGeneric())) {
    return;
  }
  auto clientResponsesBody = reader.getBody();
  if (!validateClientResponses(clientResponsesBody)) {
    return;
  }
  TypedMallocMessageBuilder<proto::SignedMessage<proto::ClientResponsesBody>>
      responses;
  responses.setTypedRoot(reader);
  backupNodesClientResponses.emplace(reader.getSign().getIdx(),
                                     std::move(responses));
  if (backupNodesClientResponses.size() == quorumSize) {
    capnp::MallocMessageBuilder recoveryBuilder;
    auto recovery =
        recoveryBuilder.initRoot<proto::SignedMessage<proto::RecoveryBody>>();
    auto recoveryBody = recovery.getBody();
    auto clientResponsesList = recoveryBody.initClientResponses(quorumSize);
    int i = 0;
    for (const auto &item : backupNodesClientResponses) {
      clientResponsesList.setWithCaveats(i, item.second.getTyped());
      i++;
    }
    signMessage(recovery.asGeneric());
    for (int j = 0; j < nodesCount; ++j) {
      sendToNode(j, MessageType::RECOVERY, recoveryBuilder);
    }
    recoverPendingChain(recoveryBody);
    transitionToLeaderFastPath();
  }
}

void ZyzaReplica::processProposal(const proto::Proposal::Reader &proposal) {
  if (currentState != ReplicaState::BACKUP_FAST) {
    return;
  }
  auto proposalSignedMessage = proposal.getSignedProposal();
  if (!validateProposal(proposalSignedMessage,
                        initPassed ? pendingChain.back().proposalHash : nullptr,
                        initPassed ? currentFastPathLeader : 0,
                        acceptedChain.size() + pendingChain.size())) {
    return;
  }
  for (const auto &ackList : proposal.getAcknowledgements2()) {
    if (pendingChain.empty()) {
      std::clog << "got acks for unknown proposal" << std::endl;
      return;
    }
    uint8_t hash2[32];
    SHA256(pendingChain.front().proposalHash, 32, hash2);
    if (!validateSignatureList(hash2, ackList)) {
      return;
    }
    auto &acceptedProposal =
        acceptedChain.emplace_back(std::move(pendingChain.front()));
    for (const auto &sign : ackList) {
      memcpy(acceptedProposal.acks2[sign.getIdx()], sign.getSign().begin(), 64);
    }
    acceptedProposal.acks1.clear();
    pendingChain.pop_front();
    std::clog << "processed ack list" << std::endl;
  }
  if (pendingChain.size() == maxPendingChainLength) {
    std::clog << "pending tail size is too long" << std::endl;
    return;
  }
  auto body = proposalSignedMessage.getBody();
  std::clog << idx << ": got valid proposal with ord " << body.getOrd()
            << std::endl;
  uint8_t newProposalHash[32];
  hashStruct(proposal.getSignedProposal(), newProposalHash);

  auto &pendingBlock = pendingChain.emplace_back();
  memcpy(pendingBlock.proposalHash, newProposalHash, 32);
  pendingBlock.proposal.setTypedRoot(proposal.getSignedProposal());
  for (auto i = unknownAcks.begin(); i != unknownAcks.end(); i++) {
    auto &unknownAck = *i;
    if (memcmp(unknownAck.proposalHash, newProposalHash, 32) != 0) {
      continue;
    }
    pendingBlock.acks1 = std::move(unknownAck.signatures);
    unknownAcks.erase(i);
    if (pendingBlock.acks1.size() == quorumSize) {
      sendAck2(pendingBlock);
    }
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
  for (int i = 0; i < nodesCount; ++i) {
    sendToNode(i, MessageType::PROPOSAL_ACK_1, ackBuilder);
  }

  backupFastPathTimeout.Cancel();
  backupFastPathTimeout = ns3::Simulator::Schedule(
      ns3::Time::From(alertTimeout.count(), ns3::Time::MS),
      [this] { handleTimeout(); });
  initPassed = true;
  std::clog << ns3::Simulator::Now().As() << ": " << idx
            << ": processed proposal" << std::endl;
}

void ZyzaReplica::processAcknowledgement1(
    const proto::Acknowledgement::Reader &reader) {
  if (reader.getHash().size() != 32) {
    std::clog << "wrong ack proposal hash size" << std::endl;
    return;
  }
  if (reader.getSign().getSign().size() != 64) {
    std::clog << "wrong ack proposal sign size" << std::endl;
    return;
  }
  if (!verifyData(reader.getHash().begin(), reader.getSign().getSign().begin(),
                  reader.getSign().getIdx())) {
    std::clog << "wrong ack proposal sign" << std::endl;
    return;
  }

  for (auto &unknownAck : unknownAcks) {
    if (memcmp(unknownAck.proposalHash, reader.getHash().begin(), 32) != 0) {
      continue;
    }
    if (unknownAck.signatures.size() == quorumSize) {
      return;
    }
    memcpy(unknownAck.signatures[reader.getSign().getIdx()],
           reader.getSign().getSign().begin(), 64);
    return;
  }
  for (auto &proposal : pendingChain) {
    if (memcmp(proposal.proposalHash, reader.getHash().begin(), 32) != 0) {
      continue;
    }
    if (proposal.acks1.size() == quorumSize) {
      return;
    }
    memcpy(proposal.acks1[reader.getSign().getIdx()],
           reader.getSign().getSign().begin(), 64);
    if (proposal.acks1.size() == quorumSize) {
      sendAck2(proposal);
    }
    return;
  }
}

void ZyzaReplica::processAcknowledgement2(
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
  if (!verifyData(reader.getHash().begin(), reader.getSign().getSign().begin(),
                  reader.getSign().getIdx())) {
    std::clog << "wrong ack proposal sign" << std::endl;
    return;
  }
  for (auto &proposal : pendingChain) {
    uint8_t hash2[32];
    SHA256(proposal.proposalHash, 32, hash2);
    if (memcmp(hash2, reader.getHash().begin(), 32) != 0) {
      continue;
    }
    if (proposal.acks2.size() == quorumSize) {
      break;
    }
    memcpy(proposal.acks2[reader.getSign().getIdx()],
           reader.getSign().getSign().begin(), 64);
    //    std::clog << "processed ack" << std::endl;
    if (proposal.acks2.size() == quorumSize &&
        memcmp(proposal.proposalHash, pendingChain.front().proposalHash, 32) ==
            0) {
      onPendingBlockAcksReady();
    }
    break;
  }
}

void ZyzaReplica::processFallbackAlert(
    const proto::SignedMessage<proto::FallbackAlertBody>::Reader
        &fallbackAlert) {
  if (currentState != ReplicaState::LEADER_FALLBACK) {
    return;
  }
  if (!validateFallbackAlert(fallbackAlert)) {
    return;
  }
  if (acceptedFallbackAlerts.size() == quorumSize) {
    std::clog << "already got enough alerts" << std::endl;
    return;
  }
  hexdump(fallbackAlert, "got fallback alert");
  acceptedFallbackAlerts[fallbackAlert.getSign().getIdx()].setTypedRoot(
      fallbackAlert);
  if (acceptedFallbackAlerts.size() == quorumSize) {
    onEnoughFallbackAlertsCollected();
  }
}

void ZyzaReplica::processRecoveryState(
    const proto::SignedMessage<proto::RecoveryStateBody>::Reader
        &recoveryState) {
  if (currentState != ReplicaState::BACKUP_FALLBACK) {
    return;
  }
  if (hasRecoveryState) {
    std::clog << "already got recovery state message" << std::endl;
    return;
  }
  if (!verifySignedMessage(recoveryState.asGeneric())) {
    return;
  }
  if (recoveryState.getSign().getIdx() != currentBackupPathLeader) {
    std::clog << "got recovery state not from current backup leader"
              << std::endl;
    return;
  }
  auto recoveryStateBody = recoveryState.getBody();
  for (const auto &fallbackAlert : recoveryStateBody.getAlerts()) {
    if (!validateFallbackAlert(fallbackAlert)) {
      return;
    }
  }
  hashStruct(recoveryState.getBody(), recoveryStateBodyHash);
  recoveryStateBuilder.reset();
  recoveryStateBuilder.setTypedRoot(recoveryState);
  hasRecoveryState = true;
  std::set<std::tuple<std::string, uint16_t, uint64_t>> requests;
  std::set<uint64_t> acceptedRequests;
  for (const auto &fallbackAlert : recoveryStateBody.getAlerts()) {
    auto fallbackAlertBody = fallbackAlert.getBody();
    uint8_t lastAcceptedHash[32];
    bool isAccepted = fallbackAlertBody.isLastAckList();
    if (fallbackAlertBody.isLastAckList()) {
      memcpy(lastAcceptedHash,
             fallbackAlertBody.getLastAckList().getProposalHash().begin(), 32);
    }
    for (const auto &proposalMessage :
         fallbackAlertBody.getUnackedSignedProposals()) {
      auto proposal = proposalMessage.getBody();
      for (const auto &req : proposal.getRequests()) {
        requests.insert({req.getRespAddr(), req.getRespPort(), req.getId()});
        if (isAccepted) {
          acceptedRequests.insert(req.getId());
        }
      }
      uint8_t proposalHash[32];
      hashStruct(proposal, proposalHash);
      if (isAccepted && memcmp(proposalHash, lastAcceptedHash, 32) == 0) {
        isAccepted = false;
      }
    }
  }
  for (const auto &[addr, port, reqId] : requests) {
    if (acceptedRequests.contains(reqId)) {
      continue;
    }
    expectedClientResponses.insert(reqId);
    capnp::MallocMessageBuilder requestCancelBuilder;
    auto requestCancel =
        requestCancelBuilder
            .initRoot<proto::SignedMessage<proto::RequestCancelBody>>();
    requestCancel.getBody().setId(reqId);
    signMessage(requestCancel.asGeneric());
    sendToClient(addr, port, MessageType::REQUEST_CANCEL, requestCancelBuilder);
  }
  // in case if node already got all required responses
  onClientResponse();
}

void ZyzaReplica::processRecovery(
    const proto::SignedMessage<proto::RecoveryBody>::Reader &recovery) {
  if (currentState != ReplicaState::BACKUP_FALLBACK) {
    return;
  }
  if (!verifySignedMessage(recovery.asGeneric())) {
    return;
  }
  auto recoveryBody = recovery.getBody();
  std::set<uint16_t> responseSenders;
  for (const auto &item : recoveryBody.getClientResponses()) {
    if (!verifySignedMessage(item.asGeneric())) {
      return;
    }
    auto clientResponsesBody = item.getBody();
    if (!validateClientResponses(clientResponsesBody)) {
      return;
    }
    responseSenders.insert(item.getSign().getIdx());
  }
  if (responseSenders.size() != quorumSize) {
    std::clog << "duplicated client responses" << std::endl;
  }
  recoverPendingChain(recoveryBody);
  currentFastPathLeader = currentBackupPathLeader;
  transitionToBackupFastPath();
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
  auto pendingBegin = pendingChain.begin();
  auto pendingEnd = pendingChain.end();
  int pendingTotalSize = pendingChain.size();
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
  auto acks1It = nsr.getAcknowledgements1().begin();
  auto acks1End = nsr.getAcknowledgements1().end();
  auto acks2It = nsr.getAcknowledgements2().begin();
  auto acks2End = nsr.getAcknowledgements2().end();
  auto pendingIt = pendingChain.begin();
  auto pendingEnd = pendingChain.end();
  bool appended = false;
  while (proposalsIt != proposalsEnd && acks2It != acks2End &&
         pendingIt != pendingEnd) {
    uint8_t hash[32];
    hashStruct(*proposalsIt, hash);
    if (memcmp(hash, pendingIt->proposalHash, 32) != 0) {
      pendingChain.clear();
      appendTail(proposalsIt, proposalsEnd, acks1It, acks1End, acks2It,
                 acks2End);
      appended = true;
      break;
    }
    auto &newAcceptedProposal =
        acceptedChain.emplace_back(std::move(pendingChain.front()));
    pendingChain.pop_front();
    for (const auto &item : *acks2It) {
      memcpy(newAcceptedProposal.acks2[item.getIdx()], item.getSign().begin(),
             64);
    }
  }
  if (pendingIt == pendingEnd) {
    appendTail(proposalsIt, proposalsEnd, acks1It, acks1End, acks2It, acks2End);
    appended = true;
  } else {
    bool diverged = false;
    while (proposalsIt != proposalsEnd && pendingIt != pendingEnd) {
      uint8_t hash[32];
      hashStruct(*proposalsIt, hash);
      if (memcmp(hash, pendingIt->proposalHash, 32) != 0) {
        diverged = true;
        break;
      }
    }
    if (!diverged) {
      if (proposalsIt != proposalsEnd) {
        appendTail(proposalsIt, proposalsEnd, acks1It, acks1End, acks2It,
                   acks2End);
        appended = true;
      }
    }
  }
  if (appended) {
    currentFastPathLeader =
        acceptedChain.back().proposal.getTyped().getSign().getIdx();
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
    currentState = ReplicaState::LEADER_FALLBACK;
    sendFallbackAlert(idx);
  } else if (currentState == ReplicaState::BACKUP_FALLBACK) {
    currentBackupPathLeader = -1;
    recoveryStateBuilder.reset();
    hasRecoveryState = false;
    clientResponses.clear();
    sentClientResponses = false;
    nextLeaderAlertTimerEvent.Cancel();
    expectedClientResponses.clear();
  }
  currentState = ReplicaState::LEADER_FALLBACK;
}

void ZyzaReplica::transitionToBackupFastPath() {
  if (currentState == ReplicaState::BACKUP_FALLBACK) {
    currentBackupPathLeader = -1;
    recoveryStateBuilder.reset();
    hasRecoveryState = false;
    memset(recoveryStateBodyHash, 0, 32);
    clientResponses.clear();
    sentClientResponses = false;
    nextLeaderAlertTimerEvent.Cancel();
  }
  currentState = ReplicaState::BACKUP_FAST;
  backupFastPathTimeout.Cancel();
  backupFastPathTimeout = ns3::Simulator::Schedule(
      ns3::Time::From(alertTimeout.count(), ns3::Time::MS),
      [this] { handleTimeout(); });
}
void ZyzaReplica::transitionToLeaderFastPath() {
  currentState = ReplicaState::LEADER_FAST;
  currentFastPathLeader = idx;
  acceptedFallbackAlerts.clear();
  backupNodesClientResponses.clear();
  expectedClientResponses.clear();
  memset(recoveryStateBodyHash, 0, 32);
  recoveryStateBuilder.reset();
  hasRecoveryState = false;
  backupFastPathTimeout.Cancel();
  backupFastPathTimeout = ns3::Simulator::Schedule(
      ns3::Time::From(alertTimeout.count(), ns3::Time::MS),
      [this] { handleTimeout(); });
}

void ZyzaReplica::onEnoughFallbackAlertsCollected() {
  capnp::MallocMessageBuilder newRecoveryStateBuilder;
  auto recoveryState =
      newRecoveryStateBuilder
          .initRoot<proto::SignedMessage<proto::RecoveryStateBody>>();
  auto alerts = recoveryState.getBody().initAlerts(quorumSize);
  std::set<std::tuple<std::string, uint16_t, uint64_t>> requests;
  std::set<uint64_t> acceptedRequests;
  int i = 0;
  for (auto &item : acceptedFallbackAlerts) {
    auto fallbackAlert = item.second.getTyped();
    alerts.setWithCaveats(i, fallbackAlert);
    hexdump(fallbackAlert.asReader(),
            "adding fallback alert to recovery state");
    auto fallbackAlertBody = fallbackAlert.getBody();
    uint8_t lastAcceptedHash[32];
    bool isAccepted = fallbackAlertBody.isLastAckList();
    if (fallbackAlertBody.isLastAckList()) {
      memcpy(lastAcceptedHash,
             fallbackAlertBody.getLastAckList().getProposalHash().begin(), 32);
    }
    for (const auto &proposalMessage :
         fallbackAlertBody.getUnackedSignedProposals().asReader()) {
      auto proposal = proposalMessage.getBody();
      for (const auto &req : proposal.getRequests()) {
        requests.insert({req.getRespAddr(), req.getRespPort(), req.getId()});
        if (isAccepted) {
          acceptedRequests.insert(req.getId());
        }
      }
      uint8_t proposalHash[32];
      hashStruct(proposalMessage, proposalHash);
      if (isAccepted && memcmp(proposalHash, lastAcceptedHash, 32) == 0) {
        isAccepted = false;
      }
    }
    i++;
  }
  for (const auto &[addr, port, reqId] : requests) {
    if (!acceptedRequests.contains(reqId)) {
      expectedClientResponses.insert(reqId);
      capnp::MallocMessageBuilder requestCancelBuilder;
      auto requestCancel =
          requestCancelBuilder
              .initRoot<proto::SignedMessage<proto::RequestCancelBody>>();
      requestCancel.getBody().setId(reqId);
      signMessage(requestCancel.asGeneric());
      sendToClient(addr, port, MessageType::REQUEST_CANCEL,
                   requestCancelBuilder);
    }
  }
  signMessage(recoveryState.asGeneric());
  hashStruct(recoveryState.getBody().asReader(), recoveryStateBodyHash);
  hexdump(recoveryStateBodyHash, "recovery state hash");
  recoveryStateBuilder.reset();
  recoveryStateBuilder.setTypedRoot(recoveryState);
  hasRecoveryState = true;
  for (int j = 0; j < nodesCount; ++j) {
    sendToNode(j, MessageType::RECOVERY_STATE, newRecoveryStateBuilder);
  }
}

void ZyzaReplica::onClientResponse() {
  if (currentState != ReplicaState::BACKUP_FALLBACK &&
      currentState != ReplicaState::LEADER_FALLBACK) {
    return;
  }
  if (!hasRecoveryState || sentClientResponses) {
    return;
  }
  for (const auto &reqId : expectedClientResponses) {
    if (!clientResponses.contains(reqId)) {
      return;
    }
  }
  capnp::MallocMessageBuilder clientResponsesBuilder;
  auto clientResponsesMessage =
      clientResponsesBuilder
          .initRoot<proto::SignedMessage<proto::ClientResponsesBody>>();
  clientResponsesMessage.getBody().setRecoveryStateBodyHash(
      {recoveryStateBodyHash, 32});
  auto responses = clientResponsesMessage.getBody().initResponses(
      expectedClientResponses.size());
  int i = 0;
  for (const auto &reqId : expectedClientResponses) {
    responses.setWithCaveats(i, clientResponses[reqId].getTyped());
    i++;
  }
  signMessage(clientResponsesMessage.asGeneric());
  sendToNode(currentBackupPathLeader, MessageType::CLIENT_RESPONSES,
             clientResponsesBuilder);
  sentClientResponses = true;
}

void ZyzaReplica::onPendingBlockAcksReady() {
  if (pendingRequests.empty()) {
    return;
  }
  startNewRound();
}

void ZyzaReplica::onRequestAccepted() {
  if (pendingChain.size() == maxPendingChainLength &&
      pendingChain.front().acks2.size() != quorumSize) {
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
  capnp::MallocMessageBuilder proposalBuilder;
  auto proposal = proposalBuilder.initRoot<proto::Proposal>();
  auto proposalBody = proposal.getSignedProposal().getBody();
  proposalBody.setPrevProposalHash({pendingChain.back().proposalHash, 32});
  proposalBody.initRequests(pendingRequests.size());
  for (int i = 0; i < pendingRequests.size(); ++i) {
    proposalBody.getRequests().setWithCaveats(i, pendingRequests[i].getTyped());
  }
  proposalBody.setOrd(acceptedChain.size() + pendingChain.size());
  signMessage(proposal.getSignedProposal().asGeneric());

  uint8_t proposalHash[32];
  hashStruct(proposal.getSignedProposal().asReader(), proposalHash);
  hexdump(proposalHash, "new round proposal hash");

  for (const auto &pendingRequest : pendingRequests) {
    responseToClient(pendingRequest.getTyped(), proposalHash);
  }
  pendingRequests.clear();

  int acceptedProposals = 0;
  for (const auto &p : pendingChain) {
    if (p.acks2.size() != quorumSize) {
      break;
    }
    acceptedProposals++;
  }
  proposal.initAcknowledgements2(acceptedProposals);
  auto it = pendingChain.begin();
  for (int i = 0; i < acceptedProposals; ++i) {
    auto d = proposal.getAcknowledgements2().init(i, quorumSize);
    int j = 0;
    for (const auto &[nodeId, sign] : it->acks2) {
      auto signature = d[j];
      signature.setIdx(nodeId);
      signature.setSign({sign, 64});
      j++;
    }
    it++;
  }
  for (int i = 0; i < acceptedProposals; ++i) {
    auto &p = acceptedChain.emplace_back(std::move(pendingChain.front()));
    p.acks1.clear();
    pendingChain.pop_front();
    initPassed = true;
  }

  for (int i = 0; i < nodesCount; ++i) {
    sendToNode(i, MessageType::PROPOSAL, proposalBuilder);
  }

  auto &newPendingProposal = pendingChain.emplace_back();
  memcpy(newPendingProposal.proposalHash, proposalHash, 32);
  newPendingProposal.proposal.setTypedRoot(proposal.getSignedProposal());
  signData(proposalHash, newPendingProposal.acks1[idx]);
  backupFastPathTimeout.Cancel();
  backupFastPathTimeout = ns3::Simulator::Schedule(
      ns3::Time::From(alertTimeout.count(), ns3::Time::MS),
      [this] { handleTimeout(); });
  std::clog << "started a new round" << std::endl;
}

void ZyzaReplica::recoverPendingChain(
    const proto::RecoveryBody::Reader &recoveryBody) {
  std::list<uint8_t[32]> acceptedByClientsProposals;
  for (const auto &item : recoveryBody.getClientResponses()) {
    auto clientResponsesBody = item.getBody();
    for (const auto &clientResponse : clientResponsesBody.getResponses()) {
      if (clientResponse.isCompleted()) {
        auto pb = clientResponse.getCompleted().getProofBody();
        bool hasProposal = false;
        for (const auto &proposalHash : acceptedByClientsProposals) {
          if (memcmp(proposalHash, pb.getImplHash().begin(), 32) == 0) {
            hasProposal = true;
          }
        }
        if (!hasProposal) {
          memcpy(acceptedByClientsProposals.emplace_back(),
                 pb.getImplHash().begin(), 32);
        }
      }
    }
  }
  auto recoveryStateSignedMessage = recoveryStateBuilder.getTyped();
  auto recoveryStateBody = recoveryStateSignedMessage.getBody();
  int maxLength = 0;
  int maxLengthIdx = 0;
  for (int j = 0; j < recoveryStateBody.getAlerts().size(); ++j) {
    auto fallbackAlert = recoveryStateBody.getAlerts()[j];
    auto fallbackAlertBody = fallbackAlert.getBody();
    uint8_t lastAcceptedHash[32];
    bool isAccepted = fallbackAlertBody.isLastAckList();
    if (fallbackAlertBody.isLastAckList()) {
      memcpy(lastAcceptedHash,
             fallbackAlertBody.getLastAckList().getProposalHash().begin(), 32);
    }
    int i = 0;
    for (const auto &proposalMessage :
         fallbackAlertBody.getUnackedSignedProposals()) {
      i++;
      uint8_t hash[32];
      hashStruct(proposalMessage.asReader(), hash);
      if (isAccepted && memcmp(hash, lastAcceptedHash, 32) == 0 &&
          maxLength < i) {
        maxLengthIdx = j;
        maxLength = i;
        isAccepted = false;
      } else {
        for (const auto &item : acceptedByClientsProposals) {
          if (maxLength < i && memcmp(item, hash, 32) == 0) {
            maxLengthIdx = j;
            maxLength = i;
          }
        }
      }
    }
  }
  pendingChain.clear();
  auto d = recoveryStateBody.getAlerts()[maxLengthIdx];
  auto fallbackAlertBody = d.getBody();
  for (auto item : fallbackAlertBody.getUnackedSignedProposals()) {
    auto proposal = item.getBody();
    uint8_t hash[32];
    hashStruct(item.asReader(), hash);
    for (const auto &req : proposal.getRequests()) {
      responseToClient(req, hash);
    }
    auto &pendingProposal = pendingChain.emplace_back();
    memcpy(pendingProposal.proposalHash, hash, 32);
    pendingProposal.proposal.setTypedRoot(item);
    uint8_t compressedSig[64];
    signData(pendingProposal.proposalHash, compressedSig);
    capnp::MallocMessageBuilder ackBuilder;
    auto ack = ackBuilder.initRoot<proto::Acknowledgement>();
    ack.setHash({pendingProposal.proposalHash, 32});
    ack.getSign().setSign({compressedSig, 64});
    ack.getSign().setIdx(idx);
    for (int i = 0; i < nodesCount; ++i) {
      sendToNode(i, MessageType::PROPOSAL_ACK_1, ackBuilder);
    }
  }
}

void ZyzaReplica::responseToClient(const proto::Request::Reader &request,
                                   uint8_t *proposalHash) {
  capnp::MallocMessageBuilder respBuilder;
  auto resp = respBuilder.initRoot<proto::Response>();
  auto respProofBody = resp.getProof().getBody();
  respProofBody.setId(request.getId());
  auto respImpl = processRequest(request.getImpl());
  uint8_t hash[32];
  SHA256(respImpl.data(), respImpl.size(), hash);
  respProofBody.setImplHash({hash, 32});
  respProofBody.setProposalHash({proposalHash, 32});
  signMessage(resp.getProof().asGeneric());
  resp.setImpl({respImpl.data(), respImpl.size()});
  sendToClient(request.getRespAddr().cStr(), request.getRespPort(),
               MessageType::RESPONSE, respBuilder);
}

void ZyzaReplica::resendChainPart(
    int sender, std::list<Proposal>::iterator acceptedChainIter,
    int acceptedChainPartSize, std::list<Proposal>::iterator pendingChainIter,
    int pendingChainPartSize) {
  capnp::MallocMessageBuilder resendChainResponseBuilder;
  auto resendChainResponse =
      resendChainResponseBuilder.initRoot<proto::ResendChainResponse>();
  auto proposals = resendChainResponse.initProposals(acceptedChainPartSize +
                                                     pendingChainPartSize);
  auto acks2 = resendChainResponse.initAcknowledgements2(acceptedChainPartSize);
  int i = 0;
  while (acceptedChainIter != acceptedChain.end()) {
    proposals.setWithCaveats(i, acceptedChainIter->proposal.getTyped());
    auto acksArr = acks2.init(i, quorumSize);
    int j = 0;
    for (const auto &[nodeId, sig] : acceptedChainIter->acks2) {
      acksArr[j].setIdx(nodeId);
      acksArr[j].setSign({sig, 64});
    }
    i++;
    acceptedChainIter++;
  }
  int ack1Count = 0;
  auto pendingChainEndIter = pendingChain.end();
  auto pendingChainIterCopy = pendingChainIter;
  while (pendingChainIter != pendingChainEndIter) {
    proposals.setWithCaveats(i, pendingChainIter->proposal.getTyped());
    if (pendingChainIter->acks1.size() == quorumSize) {
      ack1Count++;
    }
    i++;
    pendingChainIter++;
  }
  auto acks1 = resendChainResponse.initAcknowledgements1(ack1Count);
  i = 0;
  while (pendingChainIterCopy != pendingChainEndIter) {
    if (pendingChainIterCopy->acks1.size() == quorumSize) {
      acks1[i].setProposalHash({pendingChainIterCopy->proposalHash, 32});
      auto signs = acks1[i].initAcknowledgements1(quorumSize);
      int j = 0;
      for (const auto &[nodeIdx, sign] : pendingChainIterCopy->acks1) {
        signs[j].setIdx(nodeIdx);
        signs[j].setSign({sign, 64});
        j++;
      }
      i++;
    }
  }
  sendToNode(sender, MessageType::RESEND_CHAIN_RESPONSE,
             resendChainResponseBuilder);
}

void ZyzaReplica::appendTail(
    capnp::List<proto::SignedMessage<proto::ProposalBody>>::Reader::Iterator
        proposalsIt,
    capnp::List<proto::SignedMessage<proto::ProposalBody>>::Reader::Iterator
        proposalsEnd,
    capnp::List<proto::AckList>::Reader::Iterator acks1It,
    capnp::List<proto::AckList>::Reader::Iterator acks1End,
    capnp::List<capnp::List<proto::Signature>>::Reader::Iterator acks2It,
    capnp::List<capnp::List<proto::Signature>>::Reader::Iterator acks2End) {
  while (proposalsIt != proposalsEnd && acks2It != acks2End) {
    auto &newAcceptedProposal = acceptedChain.emplace_back();
    newAcceptedProposal.proposal.setTypedRoot(*proposalsIt);
    hashStruct(newAcceptedProposal.proposal.getTyped().asReader(),
               newAcceptedProposal.proposalHash);
    for (const auto &item : *acks2It) {
      memcpy(newAcceptedProposal.acks2[item.getIdx()], item.getSign().begin(),
             64);
    }
    auto proposalBody = proposalsIt->getBody();
    for (const auto &req : proposalBody.getRequests()) {
      responseToClient(req, newAcceptedProposal.proposalHash);
    }
    proposalsIt++;
    acks2It++;
  }
  while (proposalsIt != proposalsEnd) {
    auto &newPendingProposal = pendingChain.emplace_back();
    newPendingProposal.proposal.setTypedRoot(*proposalsIt);
    hashStruct(newPendingProposal.proposal.getTyped().asReader(),
               newPendingProposal.proposalHash);
    if (acks1It != acks1End &&
        memcmp(newPendingProposal.proposalHash,
               acks1It->getProposalHash().begin(), 32) == 0) {
      for (const auto &item : acks1It->getAcknowledgements1()) {
        memcpy(newPendingProposal.acks1[item.getIdx()], item.getSign().begin(),
               64);
      }
      if (newPendingProposal.acks1.size() == quorumSize) {
        sendAck2(newPendingProposal);
      }
      acks1It++;
    }
    auto proposalBody = proposalsIt->getBody();
    for (const auto &req : proposalBody.getRequests()) {
      responseToClient(req, newPendingProposal.proposalHash);
    }
    uint8_t compressedSig[64];
    signData(newPendingProposal.proposalHash, compressedSig);
    capnp::MallocMessageBuilder ackBuilder;
    auto ack = ackBuilder.initRoot<proto::Acknowledgement>();
    ack.setHash({newPendingProposal.proposalHash, 32});
    ack.getSign().setSign({compressedSig, 64});
    ack.getSign().setIdx(idx);
    for (int i = 0; i < nodesCount; ++i) {
      sendToNode(i, MessageType::PROPOSAL_ACK_1, ackBuilder);
    }
    proposalsIt++;
  }
}

void ZyzaReplica::sendFallbackAlert(uint16_t nodeIdx) {
  capnp::MallocMessageBuilder fallbackAlertBuilder;
  auto fallbackAlert =
      fallbackAlertBuilder
          .initRoot<proto::SignedMessage<proto::FallbackAlertBody>>();
  auto fallbackAlertBody = fallbackAlert.getBody();
  fallbackAlertBody.setLastAckedProposalHash(
      {acceptedChain.back().proposalHash, 32});
  auto unackedProposals =
      fallbackAlertBody.initUnackedSignedProposals(pendingChain.size());
  int i = 0;
  for (const auto &pendingProposal : pendingChain) {
    unackedProposals.setWithCaveats(i, pendingProposal.proposal.getTyped());
    i++;
  }
  Proposal *proposalWithAck = nullptr;
  for (auto &pendingProposal : pendingChain) {
    if (!pendingProposal.acks1.empty()) {
      proposalWithAck = &pendingProposal;
    }
  }
  if (proposalWithAck == nullptr) {
    fallbackAlertBody.setNoAckList();
  } else {
    auto ackList = fallbackAlertBody.initLastAckList();
    ackList.setProposalHash({proposalWithAck->proposalHash, 32});
    auto list = ackList.initAcknowledgements1(quorumSize);
    i = 0;
    for (const auto &[nodeId, sig] : proposalWithAck->acks1) {
      list[i].setIdx(nodeId);
      list[i].setSign({sig, 64});
      i++;
    }
  }
  signMessage(fallbackAlert.asGeneric());
  sendToNode(nodeIdx, MessageType::FALLBACK_ALERT, fallbackAlertBuilder);
}

void ZyzaReplica::sendAck2(const Proposal &proposal) {
  uint8_t hash2[32];
  SHA256(proposal.proposalHash, 32, hash2);
  uint8_t compressedSig[64];
  signData(hash2, compressedSig);
  capnp::MallocMessageBuilder acknowledgementBuilder;
  auto acknowledgement =
      acknowledgementBuilder.initRoot<proto::Acknowledgement>();
  acknowledgement.setHash({hash2, 32});
  auto sign = acknowledgement.initSign();
  sign.setIdx(idx);
  sign.setSign({compressedSig, 64});
  sendToNode(currentFastPathLeader, MessageType::PROPOSAL_ACK_2,
             acknowledgementBuilder);
}

void ZyzaReplica::handleTimeout() {
  std::clog << ns3::Simulator::Now().As() << ": " << idx
            << ": timer timeout: " << ((int)currentState) << std::endl;
  uint16_t backupLeader;
  if (currentState == ReplicaState::BACKUP_FALLBACK) {
    backupLeader = (currentBackupPathLeader + 1) % nodesCount;
  } else {
    backupLeader = (currentFastPathLeader + 1) % nodesCount;
  }

  if (backupLeader == idx) {
    currentBackupPathLeader = idx;
    transitionToLeaderFallbackPath();
  } else {
    if (currentState != ReplicaState::BACKUP_FALLBACK) {
      currentBackupPathLeader = currentFastPathLeader;
    }
    transitionToNextBackupLeader();
  }
}

void ZyzaReplica::sendToClient(const std::string &dstIp, uint16_t dstPort,
                               MessageType messageType,
                               capnp::MessageBuilder &message) {
  uint64_t msgId = 0;
  fillRandom(&msgId, sizeof(msgId));
  auto unpackedBytes = capnp::computeSerializedSizeInWords(message) * 8;
  // max compression overhead is 2 bytes per 2KB
  auto maxPackedBytes = ((unpackedBytes + 2048 - 1) / 2048) * (2048 + 2);
  uint32_t maxSize = maxPackedBytes + sizeof(MessageHeader);
  auto data = std::make_unique<uint8_t[]>(maxSize);
  kj::ArrayOutputStream aos(
      {data.get() + sizeof(MessageHeader), maxPackedBytes});
  capnp::writePackedMessage(aos, message);
  auto compressedMsgSize =
      aos.getWriteBuffer().begin() - (data.get() + sizeof(MessageHeader));
  auto realMsgSize = compressedMsgSize + sizeof(MessageHeader);
  new (data.get()) MessageHeader(realMsgSize, static_cast<uint16_t>(idx),
                                 static_cast<uint16_t>(messageType), msgId);

  ns3::Address sinkAddress(ns3::InetSocketAddress(dstIp.c_str(), dstPort));
  std::clog << ns3::Simulator::Now().As() << ": " << idx << ": sending message "
            << messageTypeToString(messageType) << " of size " << realMsgSize
            << " to client. msgId: " << std::hex << msgId << std::dec
            << std::endl;
  serverUdpSocket->SendTo(data.get(), realMsgSize, 0, sinkAddress);
}

void ZyzaReplica::sendToNode(int node, MessageType messageType,
                             capnp::MessageBuilder &message) {
  NS_LOG_DEBUG(idx << " " << ns3::Simulator::Now().As(ns3::Time::S)
                   << " sending message " << messageTypeToString(messageType)
                   << " to " << node);
  auto h = activeNodeConnections[node];
  uint64_t msgId = 0;
  fillRandom(&msgId, sizeof(msgId));
  auto unpackedBytes = capnp::computeSerializedSizeInWords(message) * 8;
  // max compression overhead is 2 bytes per 2KB
  auto maxPackedBytes = ((unpackedBytes + 2048 - 1) / 2048) * (2048 + 2);
  uint32_t maxSize = maxPackedBytes + sizeof(MessageHeader);
  auto data = std::make_unique<uint8_t[]>(maxSize);
  kj::ArrayOutputStream aos(
      {data.get() + sizeof(MessageHeader), maxPackedBytes});
  capnp::writePackedMessage(aos, message);
  auto compressedMsgSize =
      aos.getWriteBuffer().begin() - (data.get() + sizeof(MessageHeader));
  auto realMsgSize = compressedMsgSize + sizeof(MessageHeader);
  new (data.get()) MessageHeader(realMsgSize, static_cast<uint16_t>(idx),
                                 static_cast<uint16_t>(messageType), msgId);
  if (h != nullptr) {
    std::clog << ns3::Simulator::Now().As() << ": " << idx
              << ": sending message " << messageTypeToString(messageType)
              << " of size " << realMsgSize << " to " << node
              << " msgId: " << std::hex << msgId << std::dec << std::endl;
    h->Send(reinterpret_cast<const uint8_t *>(data.get()), realMsgSize, 0);
  } else {
    std::clog << ns3::Simulator::Now().As() << ": " << idx
              << ": adding pending message " << messageTypeToString(messageType)
              << " to " << node << " msgId: " << std::hex << msgId << std::dec
              << std::endl;
    pendingNodeMessages[node].emplace_back(std::move(data), realMsgSize);
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

void ZyzaReplica::signMessage(
    proto::SignedMessage<capnp::AnyPointer>::Builder unsignedMessage) {
  uint8_t hash[32];
  hashStruct(unsignedMessage.getBody(), hash);
  auto sign = unsignedMessage.getSign();
  sign.setIdx(idx);
  signData(hash, sign.initSign(64).begin());
}

bool ZyzaReplica::validateProposal(
    const proto::SignedMessage<proto::ProposalBody>::Reader &proposal,
    const uint8_t *expectedPrevProposalHash, int expectedProposalSigner,
    int proposalIndex) {
  if (!verifySignedMessage(proposal.asGeneric())) {
    return false;
  }
  auto body = proposal.getBody();
  if (proposalIndex != -1 && body.getOrd() != proposalIndex) {
    std::clog << "wrong proposal index " << body.getOrd() << ", expected "
              << proposalIndex << std::endl;
    return false;
  }
  if (proposal.getSign().getSign().size() != 64) {
    std::clog << "wrong proposal sign size" << std::endl;
    return false;
  }
  if (expectedProposalSigner != -1) {
    if (proposal.getSign().getIdx() != expectedProposalSigner) {
      std::clog << "wrong proposal signer" << std::endl;
      return false;
    }
  }
  if (body.getPrevProposalHash().size() != 32) {
    std::clog << "wrong proposal hash size" << std::endl;
    return false;
  }
  if (expectedPrevProposalHash != nullptr) {
    if (memcmp(expectedPrevProposalHash, body.getPrevProposalHash().begin(),
               32) != 0) {
      hexdump(body.getPrevProposalHash().begin(), "wrong proposal hash");
      hexdump(expectedPrevProposalHash, "expected hash");
      return false;
    }
  }
  for (const auto &req : body.getRequests()) {
    if (req.getRespAddr().size() == 0 || !req.hasImpl()) {
      std::clog << "wrong request" << std::endl;
      return false;
    }
  }
  return true;
}

bool ZyzaReplica::validateSignatureList(
    const uint8_t *proposalHash,
    const capnp::List<proto::Signature>::Reader ackList) {

  if (ackList.size() != quorumSize) {
    std::clog << "wrong ack list size" << std::endl;
    return false;
  }
  std::set<uint16_t> signatures;
  for (const auto &sign : ackList) {
    if (sign.getSign().size() != 64) {
      std::clog << "wrong ack signature size" << std::endl;
      return false;
    }
    if (!verifyData(proposalHash, sign.getSign().begin(), sign.getIdx())) {
      std::clog << "wrong signature" << std::endl;
      return false;
    }
    signatures.insert(sign.getIdx());
  }
  if (signatures.size() != quorumSize) {
    std::clog << "duplicated acks in ack list" << std::endl;
    return false;
  }
  return true;
}

bool ZyzaReplica::validateResendChainResponse(
    const proto::ResendChainResponse::Reader &nsr) {
  if (nsr.getProposals().size() <= nsr.getAcknowledgements2().size() ||
      nsr.getProposals().size() >
          nsr.getAcknowledgements2().size() + maxPendingChainLength ||
      nsr.getProposals().size() - nsr.getAcknowledgements2().size() <
          nsr.getAcknowledgements1().size()) {
    std::clog << "wrong size of chain" << std::endl;
    return false;
  }
  if (nsr.getProposals().size() == 0) {
    return true;
  }
  auto proposalsIt = nsr.getProposals().begin();
  auto proposalsEnd = nsr.getProposals().end();
  auto acks1It = nsr.getAcknowledgements1().begin();
  auto acks1End = nsr.getAcknowledgements1().end();
  auto acks2It = nsr.getAcknowledgements2().begin();
  auto acks2End = nsr.getAcknowledgements2().end();
  int lastSigner = acceptedChain.back().proposal.getTyped().getSign().getIdx();
  uint8_t prevProposalHash[32];
  memcpy(prevProposalHash, acceptedChain.back().proposalHash, 32);
  while (proposalsIt != proposalsEnd) {
    auto signedMessage = *proposalsIt;
    int expectedLeader =
        (acks1It == acks1End && acks2It == acks2End) ? lastSigner : -1;
    int expectedIndex =
        acceptedChain.size() + (proposalsIt - nsr.getProposals().begin());
    if (!validateProposal(signedMessage, acceptedChain.back().proposalHash,
                          expectedLeader, expectedIndex)) {
      return false;
    }
    hashStruct(signedMessage.getBody(), prevProposalHash);
    uint8_t hash2[32];
    SHA256(prevProposalHash, 32, hash2);
    if (acks2It != acks2End && !validateSignatureList(hash2, *acks2It)) {
      return false;
    }
    if (acks2It == acks2End) {
      if (acks1It->getProposalHash().size() != 32) {
        std::clog << "wrong ack list proposal hash size" << std::endl;
        return false;
      }
      if (memcmp(acks1It->getProposalHash().begin(), prevProposalHash, 32) ==
          0) {
        if (!validateSignatureList(prevProposalHash,
                                   acks1It->getAcknowledgements1())) {
          return false;
        } else {
          acks1It++;
        }
      }
    }
    lastSigner = proposalsIt->getSign().getIdx();
    proposalsIt++;
    acks2It++;
  }
  return acks1It == acks1End && acks2It == acks2End;
}

bool ZyzaReplica::validateFallbackAlert(
    const proto::SignedMessage<proto::FallbackAlertBody>::Reader
        &fallbackAlert) {
  if (!verifySignedMessage(fallbackAlert.asGeneric())) {
    return false;
  }
  auto fallbackAlertBody = fallbackAlert.getBody();
  if (fallbackAlertBody.getUnackedSignedProposals().size() == 0) {
    std::clog << "node sent no unacked signed proposals" << std::endl;
    return false;
  }
  if (fallbackAlertBody.hasLastAckList() &&
      fallbackAlertBody.getLastAckList().getProposalHash().size() != 32) {
    std::clog << "wrong fallback alert last ack list proposal hash size"
              << std::endl;
    return false;
  }
  if (fallbackAlertBody.getLastAckedProposalHash().size() != 32) {
    std::clog << "wrong fallback alert last acked proposal hash size"
              << std::endl;
    return false;
  }
  if (memcmp(fallbackAlertBody.getLastAckedProposalHash().begin(),
             acceptedChain.back().proposalHash, 32) != 0) {
    std::clog << "wrong fallback alert last acked proposal hash" << std::endl;
    return false;
  }
  auto proposals = fallbackAlertBody.getUnackedSignedProposals();
  if (proposals.size() > maxPendingChainLength) {
    std::clog << "wrong size of chain" << std::endl;
    return false;
  }
  uint8_t prevProposalHash[32];
  memcpy(prevProposalHash, acceptedChain.back().proposalHash, 32);
  bool passedLastAckList = !fallbackAlertBody.hasLastAckList();
  int lastSigner = currentFastPathLeader;
  for (int i = 0; i < proposals.size(); ++i) {
    auto proposalSignedMessage = proposals[i];
    if (!validateProposal(proposalSignedMessage, prevProposalHash,
                          passedLastAckList ? lastSigner : -1,
                          acceptedChain.size() + i)) {
      return false;
    }
    lastSigner = proposalSignedMessage.getSign().getIdx();
    hashStruct(proposals[i], prevProposalHash);
    if (fallbackAlertBody.hasLastAckList() &&
        memcmp(prevProposalHash,
               fallbackAlertBody.getLastAckList().getProposalHash().begin(),
               32) == 0) {
      if (!validateSignatureList(
              prevProposalHash,
              fallbackAlertBody.getLastAckList().getAcknowledgements1())) {
        return false;
      }
      passedLastAckList = true;
    }
  }
  return true;
}

bool ZyzaReplica::validateClientResponse(
    const proto::ClientResponse::Reader &clientResponse) {
  if (clientResponse.isCanceled()) {
    auto canceled = clientResponse.getCanceled();
    capnp::MallocMessageBuilder requestCancelBodyBuilder;
    auto requestCancelBody =
        requestCancelBodyBuilder.initRoot<proto::RequestCancelBody>();
    requestCancelBody.setId(clientResponse.getId());
    requestCancelBody.setBackupLeader(canceled.getBackupLeader());
    uint8_t hash[32];
    hashStruct(requestCancelBody.asReader(), hash);
    if (!validateSignatureList(hash, canceled.getProof())) {
      return false;
    }
  } else {
    auto completed = clientResponse.getCompleted();
    if (completed.getProofBody().getId() != clientResponse.getId()) {
      std::clog << "client response and proof id mismatch" << std::endl;
      return false;
    }
    uint8_t hash[32];
    hashStruct(completed.getProofBody(), hash);
    if (!validateSignatureList(hash, completed.getProof())) {
      return false;
    }
  }
  return true;
}

bool ZyzaReplica::validateClientResponses(
    const proto::ClientResponsesBody::Reader &clientResponsesBody) {
  std::set<uint64_t> requests;
  if (clientResponsesBody.getRecoveryStateBodyHash().size() != 32) {
    std::clog << "wrong recovery state body hash size" << std::endl;
    return false;
  }
  if (memcmp(clientResponsesBody.getRecoveryStateBodyHash().begin(),
             recoveryStateBodyHash, 32) != 0) {
    std::clog << "wrong recovery state body hash" << std::endl;
    return false;
  }
  for (const auto &clientResponse : clientResponsesBody.getResponses()) {
    if (requests.contains(clientResponse.getId())) {
      std::clog << "duplicated client response" << std::endl;
      return false;
    }
    if (!validateClientResponse(clientResponse)) {
      return false;
    }
    requests.insert(clientResponse.getId());
  }
  if (requests != expectedClientResponses) {
    std::clog << "got unexpected set of client responses" << std::endl;
    return false;
  }
  return true;
}

void ZyzaReplica::signData(const uint8_t *hash, uint8_t *result) {
  secp256k1_ecdsa_signature sig;
  auto *secpCtx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
  uint8_t seed[32];
  fillRandom(seed, 32);
  int rc = secp256k1_context_randomize(secpCtx, seed);
  assert(rc == 1);
  rc = secp256k1_ecdsa_sign(secpCtx, &sig, hash, seckey, nullptr, nullptr);
  assert(rc == 1);
  rc = secp256k1_ecdsa_signature_serialize_compact(secpCtx, result, &sig);
  assert(rc == 1);
  secp256k1_context_destroy(secpCtx);
  memset(seed, 0, 32);
}
} // namespace zyza
