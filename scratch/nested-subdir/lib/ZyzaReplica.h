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

namespace zyza
{
class ZyzaReplica : public Endpoint, public ZyzaCommon, public ns3::Application
{
  public:
    ZyzaReplica(int nodesCount,
                int idx,
                ns3::PointToPointStarHelper& p2psh,
                std::vector<std::vector<uint8_t>>& serializedPublicKeys,
                std::span<const uint8_t> privateKey,
                std::chrono::milliseconds fallbackTimeout);

    ~ZyzaReplica() noexcept override {};

  private:
    void StartApplication() override;

  protected:
    virtual std::vector<uint8_t> processRequest(std::span<const uint8_t> request);

    void onListeningStart() override;

    void onTcpMessage(std::span<const uint8_t> message) override;

    void onUdpMessage(std::span<const uint8_t> message) override;

  private:
    void startNewRound();

    void processRequest(const proto::Request::Reader& reader);

    void processProposal(const proto::Proposal::Reader& proposal);

    void processProposalKeepRequest(const proto::ProposalKeepRequest::Reader& proposalKeepRequest);

    void processAcknowledgement(const proto::Acknowledgement::Reader& ack);

    void processFallbackAlert(const proto::FallbackAlert::Reader& fallbackAlert);

    void processRecovery(const proto::Recovery::Reader& recovery);

    void processResendChainRequest(const proto::ResendChainRequest::Reader& nsr);

    void processResendChainResponse(const proto::ResendChainResponse::Reader& nsr);

    void recoverWithProposal(const proto::Proposal::Reader& proposal);

    void sendToClient(const std::string& dstIp,
                      uint16_t dstPort,
                      MessageType messageType,
                      capnp::MessageBuilder& message);

    void sendToNode(int node, MessageType messageType, capnp::MessageBuilder& message);

    void restartConnectionToNode(int i);

    void responseToClient(const proto::Request::Reader& request, uint8_t* proposalHash);

    void sendPendingNodeMessages(int i);

    void resendChainPart(
        std::list<std::pair<uint8_t[32], capnp::MallocMessageBuilder>>::iterator it,
        int idx,
        int partSize);

    void sendDropRequests();

    void broadcastRecovery();

    void switchToFallback();

    void startLeaderZeroNode();

    bool signData(const uint8_t* data, size_t size, uint8_t* result);

    bool signData(const uint8_t* hash, uint8_t* result);

    bool validateData(const capnp::Data::Reader& data, const proto::Signature::Reader& signature);

    bool validateData(const uint8_t* hash, const uint8_t* sign, int signer);

    bool validateQuorumCertificate(const proto::QuorumCertificate::Reader& reader,
                                   uint8_t* expectedResponseProposalHash);
    // parameters
    int idx;
    uint8_t seckey[32];
    std::chrono::milliseconds alertTimeout;
    int maxPendingChainLength;

    // backup node fast path variables
    int currentFastPathLeader;
    std::list<std::pair<uint8_t[32], capnp::MallocMessageBuilder>> acceptedChain;
    std::list<std::pair<uint8_t[32], capnp::MallocMessageBuilder>> pendingChain;
    //    std::shared_ptr<uvw::timer_handle> fallbackTimer;
    ns3::EventId alertTimerEvent;

    // backup node fallback path variables
    int currentBackupPathLeader;
    std::unique_ptr<capnp::MallocMessageBuilder> recoveryMessageBuilder;
    uint8_t recoveryMessageHash[32];
    std::set<uint16_t> recoveryAcks;

    // leader node fallback path variables
    std::map<uint16_t, capnp::MallocMessageBuilder> acceptedFallbackAlerts;
    std::map<uint8_t[32], capnp::MallocMessageBuilder> proposalStatuses;

    // leader node fast path variables
    std::vector<std::unique_ptr<capnp::MallocMessageBuilder>> pendingRequests;
    std::map<uint8_t[32], std::map<uint16_t, uint8_t[64]>> pendingProposalAcks;

    // common variables
    enum class ReplicaState
    {
        BACKUP_FAST = 1,
        BACKUP_FALLBACK = 2,
        LEADER_FAST = 3,
        LEADER_FALLBACK = 4
    } currentState;
    int proposalOrd;
    std::map<uint16_t, std::vector<std::pair<std::unique_ptr<char[]>, uint32_t>>>
        pendingNodeMessages;
    bool initPassed;

    ns3::Time last;
    ns3::Time start;
    std::chrono::system_clock::duration sum;
    int sumCount;
    uint64_t sentStatistics = 0;
    uint64_t sentMsgSize = 0;
    ns3::PointToPointStarHelper& p2psh;
    std::vector<ns3::Ptr<ns3::Socket>> activeNodeConnections;
};
} // namespace zyza

#endif // ZYZZYVA_A_ZYZAREPLICA_H
