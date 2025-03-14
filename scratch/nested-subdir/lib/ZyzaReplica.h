#ifndef ZYZZYVA_A_ZYZAREPLICA_H
#define ZYZZYVA_A_ZYZAREPLICA_H

#include "../../src/point-to-point-layout/model/point-to-point-star.h"
#include "Endpoint.h"
#include "MessageHeader.h"
#include "MessageType.h"
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
  ZyzaReplica(int nodesCount, int idx, ns3::PointToPointStarHelper &p2psh,
              std::vector<std::vector<uint8_t>> &serializedPublicKeys,
              std::span<const uint8_t> privateKey,
              std::chrono::milliseconds alertTimeout,
              std::chrono::milliseconds leaderSwitchTimeout,
              int maxPendingChainLength);

  ~ZyzaReplica() noexcept override = default;

private:
  void StartApplication() override;

  void StopApplication() override;

  void startupLeader();

  void startupBackup();

protected:
  virtual std::vector<uint8_t> processRequest(std::span<const uint8_t> request);

  void onListeningStart() override;

  void onTcpMessage(std::span<const uint8_t> message) override;

  void onUdpMessage(std::span<const uint8_t> message) override;

private:
  void processRequest(const proto::Request::Reader &reader);

  void processClientResponse(const proto::ClientResponse::Reader &reader);

  void processClientResponses(const proto::SignedMessage::Reader &reader);

  void processProposal(const proto::Proposal::Reader &proposal);

  void processAcknowledgement1(const proto::Acknowledgement::Reader &ack);

  void processAcknowledgement2(const proto::Acknowledgement::Reader &ack);

  void processFallbackAlert(const proto::SignedMessage::Reader &fallbackAlert);

  void processRecoveryState(const proto::SignedMessage::Reader &recoveryState);

  void processRecovery(const proto::SignedMessage::Reader &recovery);

  void processResendChainRequest(const proto::ResendChainRequest::Reader &nsr);

  void
  processResendChainResponse(const proto::ResendChainResponse::Reader &nsr);

  void transitionToNextBackupLeader();

  void transitionToLeaderFallbackPath();

  void transitionToBackupFastPath();

  void transitionToLeaderFastPath();

  void onEnoughFallbackAlertsCollected();

  void onClientResponse();

  void onPendingBlockAcksReady();

  void onRequestAccepted();

  void startNewRound();

  void recoverPendingChain(const proto::RecoveryBody::Reader &recoveryBody);

  void responseToClient(const proto::Request::Reader &request,
                        uint8_t *proposalHash);

  struct Proposal {
    uint8_t proposalHash[32];
    std::map<uint16_t, uint8_t[64]> acks1;
    std::map<uint16_t, uint8_t[64]> acks2;
    std::vector<uint8_t> proposal;
    Proposal() = default;
    Proposal(Proposal &&m) = default;
  };

  void resendChainPart(int sender,
                       std::list<Proposal>::iterator acceptedChainIter,
                       int acceptedChainPartSize,
                       std::list<Proposal>::iterator pendingChainIter,
                       int pendingChainPartSize);

  void sendFallbackAlert(uint16_t nodeIdx);

  void sendAck2(const Proposal &proposal);

  void appendTail(
      capnp::List<capnp::Data>::Reader::Iterator proposalsIt,
      capnp::List<capnp::Data>::Reader::Iterator proposalsEnd,
      capnp::List<proto::AckList>::Reader::Iterator acks1It,
      capnp::List<proto::AckList>::Reader::Iterator acks1End,
      capnp::List<capnp::List<proto::Signature>>::Reader::Iterator acks2It,
      capnp::List<capnp::List<proto::Signature>>::Reader::Iterator acks2End);

  void handleTimeout();

  void sendToClient(const std::string &dstIp, uint16_t dstPort,
                    MessageType messageType, capnp::MessageBuilder &message);

  void sendToNode(int node, MessageType messageType,
                  capnp::MessageBuilder &message);

  void restartConnectionToNode(int i);

  void sendPendingNodeMessages(int i);

  void createSignedMessage(capnp::MallocMessageBuilder &body,
                           capnp::MallocMessageBuilder &message);

  bool validateProposal(const proto::SignedMessage::Reader &proposal,
                        const uint8_t *expectedPrevProposalHash,
                        int expectedProposalSigner, int proposalIndex);

  bool
  validateSignatureList(const uint8_t *proposalHash,
                        const capnp::List<proto::Signature>::Reader ackList);

  bool
  validateResendChainResponse(const proto::ResendChainResponse::Reader &nsr);

  bool validateFallbackAlert(const proto::SignedMessage::Reader &fallbackAlert);

  bool
  validateClientResponse(const proto::ClientResponse::Reader &clientResponse);

  bool validateClientResponses(
      const proto::ClientResponsesBody::Reader &clientResponsesBody);

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
  ns3::EventId backupFastPathTimeout;

  // backup node fallback path variables
  uint16_t currentBackupPathLeader;
  bool sentClientResponses;
  ns3::EventId nextLeaderAlertTimerEvent;

  // leader node fallback path variables
  std::map<uint16_t, std::unique_ptr<capnp::MallocMessageBuilder>>
      acceptedFallbackAlerts;
  std::map<uint16_t, std::unique_ptr<capnp::MallocMessageBuilder>>
      backupNodesClientResponses;

  // leader node fast path variables
  std::vector<std::unique_ptr<capnp::MallocMessageBuilder>> pendingRequests;

  // common fallback path variables
  std::set<uint64_t> expectedClientResponses;
  uint8_t recoveryStateBodyHash[32];
  std::unique_ptr<capnp::MallocMessageBuilder> recoveryStateBuilder;
  std::map<uint64_t, std::unique_ptr<capnp::MallocMessageBuilder>>
      clientResponses;

  // common variables
  enum class ReplicaState {
    BACKUP_FAST = 1,
    BACKUP_FALLBACK = 2,
    LEADER_FAST = 3,
    LEADER_FALLBACK = 4
  } currentState;
  std::map<uint16_t, std::vector<std::pair<std::unique_ptr<char[]>, uint32_t>>>
      pendingNodeMessages;
  bool initPassed;
  std::list<Proposal> acceptedChain;
  struct UnknownAckList {
    uint8_t proposalHash[32];
    std::map<uint16_t, uint8_t[64]> signatures;
  };
  std::list<UnknownAckList> unknownAcks;
  std::list<Proposal> pendingChain;

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
