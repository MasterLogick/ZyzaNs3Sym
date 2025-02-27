#ifndef ZYZZYVA_A_ZYZAREPLICA_H
#define ZYZZYVA_A_ZYZAREPLICA_H

#include "../../src/point-to-point-layout/model/point-to-point-star.h"
#include "Endpoint.h"
#include "FallbackRequestState.h"
#include "MessageHeader.h"
#include "ZyzaCommon.h"
#include "lib/zyza.capnp.h"

#include "ns3/applications-module.h"
#include "ns3/internet-module.h"
#include "ns3/network-module.h"

#include <capnp/message.h>
#include <chrono>
#include <cstdint>
#include <map>
#include <secp256k1.h>
#include <span>
#include <vector>

namespace zyza {
class ZyzaReplica : public Endpoint,
                    public ZyzaCommon,
                    public ns3::Application {
public:
  ZyzaReplica(int nodesCount, int cancelersPerProposal, int idx,
              ns3::PointToPointStarHelper &p2psh,
              std::vector<std::vector<uint8_t>> &serializedPublicKeys,
              std::span<const uint8_t> privateKey,
              std::chrono::milliseconds fallbackTimeout);

  ~ZyzaReplica() noexcept override = default;

private:
  void StartApplication() override;

protected:
  virtual std::vector<uint8_t> processRequest(std::span<const uint8_t> request);

  void onListeningStart() override;

  void onTcpMessage(std::span<const uint8_t> message) override;

  void onUdpMessage(std::span<const uint8_t> message) override;

private:
  void processRequest(const proto::Request::Reader &reader);

  void processClientResponse(const proto::ClientResponse::Reader &reader);

  void processProposal(const proto::Proposal::Reader &proposal);

  void processAcknowledgement(const proto::Acknowledgement::Reader &ack);

  void processFallbackAlert(const proto::SignedMessage::Reader &fallbackAlert);

  void processProposalCancelRequest(
      const proto::SignedMessage::Reader &proposalCancelRequest);

  void processProposalCancelResponse(
      const proto::SignedMessage::Reader &proposalCancelResponse);

  void processRecovery(const proto::SignedMessage::Reader &recovery);

  void processRecoveryAck(const proto::RecoveryAck::Reader &recoveryAck);

  void processResendChainRequest(const proto::ResendChainRequest::Reader &nsr);

  void
  processResendChainResponse(const proto::ResendChainResponse::Reader &nsr);

  void transitionToNextBackupLeader();

  void transitionToLeaderFallbackPath();

  void transitionToBackupFastPath();

  void onPendingBlockAcksReady();

  void onRequestAccepted();

  void startNewRound();

  void responseToClient(const proto::Request::Reader &request,
                        uint8_t *proposalHash);

  struct Proposal {
    uint8_t proposalHash[32];
    std::map<uint16_t, uint8_t[64]> acks;
    std::vector<uint8_t> proposal;
    Proposal() = default;
    Proposal(Proposal &&m) = default;
  };

  void resendChainPart(int nodeIdx,
                       std::list<Proposal>::iterator acceptedChainIter,
                       int acceptedChainPartSize,
                       std::list<Proposal>::iterator pendingChainIter,
                       int pendingChainPartSize);

  struct PendingProposalCancelRequest {
    uint8_t proposalHash[32];
    int clientCount;
    std::map<uint64_t, std::unique_ptr<capnp::MallocMessageBuilder>>
        clientResponses;
    std::set<uint16_t> reporters;
  };

  void sendProposalCancelResponse(PendingProposalCancelRequest &pendingRequest,
                                  uint16_t nodeIdx);

  void sendFallbackAlert(uint16_t nodeIdx);

  void appendTail(
      capnp::List<capnp::Data>::Reader::Iterator proposalsIt,
      capnp::List<capnp::Data>::Reader::Iterator proposalsEnd,
      capnp::List<capnp::List<proto::Signature>>::Reader::Iterator acksIt,
      capnp::List<capnp::List<proto::Signature>>::Reader::Iterator acksEnd);

  void handleTimeout();

  void sendToClient(const std::string &dstIp, uint16_t dstPort,
                    MessageType messageType, capnp::MessageBuilder &message);

  void sendToNode(int node, MessageType messageType,
                  capnp::MessageBuilder &message);

  void restartConnectionToNode(int i);

  void sendPendingNodeMessages(int i);

  void createSignedMessage(capnp::MallocMessageBuilder &body,
                           capnp::MallocMessageBuilder &message);

  bool validateAckList(const uint8_t *proposalHash,
                       const capnp::List<proto::Signature>::Reader ackList);

  bool
  validateResendChainResponse(const proto::ResendChainResponse::Reader &nsr);

  void signData(const uint8_t *data, size_t size, uint8_t *result);

  void signData(const uint8_t *hash, uint8_t *result);

  // parameters
  int idx;
  uint8_t seckey[32];
  std::chrono::milliseconds alertTimeout;
  std::chrono::milliseconds leaderSwitchTimeout;
  int maxPendingChainLength;

  // backup node fast path variables
  uint16_t currentFastPathLeader;
  std::list<Proposal> pendingChain;
  ns3::EventId backupFastPathTimeout;

  // backup node fallback path variables
  uint16_t currentBackupPathLeader;
  std::unique_ptr<capnp::MallocMessageBuilder> recoveryMessageBuilder;
  uint8_t recoveryMessageHash[32];
  std::set<uint16_t> recoveryAcks;
  ns3::EventId nextLeaderAlertTimerEvent;

  // leader node fallback path variables
  std::map<uint16_t, capnp::MallocMessageBuilder> acceptedFallbackAlerts;
  std::map<uint8_t[32], capnp::MallocMessageBuilder> proposalStatuses;

  // leader node fast path variables
  std::vector<std::unique_ptr<capnp::MallocMessageBuilder>> pendingRequests;
  std::list<Proposal> pendingProposals;

  // common variables
  enum class ReplicaState {
    BACKUP_FAST = 1,
    BACKUP_FALLBACK = 2,
    LEADER_FAST = 3,
    LEADER_FALLBACK = 4
  } currentState;
  int proposalOrd;
  std::map<uint16_t, std::vector<std::pair<std::unique_ptr<char[]>, uint32_t>>>
      pendingNodeMessages;
  bool initPassed;
  std::list<Proposal> acceptedChain;
  std::list<PendingProposalCancelRequest> pendingProposalCancelRequests;
  std::list<std::pair<uint8_t[32], std::set<uint16_t>>> keepedAcksInfo;

  ns3::Time last;
  ns3::Time start;
  std::chrono::system_clock::duration sum;
  int sumCount;
  uint64_t sentStatistics = 0;
  uint64_t sentMsgSize = 0;
  ns3::PointToPointStarHelper &p2psh;
  std::vector<ns3::Ptr<ns3::Socket>> activeNodeConnections;
};
} // namespace zyza

#endif // ZYZZYVA_A_ZYZAREPLICA_H
