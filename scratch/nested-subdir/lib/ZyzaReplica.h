#ifndef ZYZZYVA_A_ZYZAREPLICA_H
#define ZYZZYVA_A_ZYZAREPLICA_H

#include "Endpoint.h"
#include "MessageHeader.h"
#include "lib/zyza.capnp.h"

#include "ns3/applications-module.h"
#include "ns3/internet-module.h"
#include "ns3/network-module.h"
#include "../../src/point-to-point-layout/model/point-to-point-star.h"

#include <capnp/message.h>
#include <chrono>
#include <cstdint>
#include <map>
#include <secp256k1.h>
#include <span>
#include <vector>

namespace zyza
{
class ZyzaReplica : public Endpoint, public ns3::Application
{
  public:
    ZyzaReplica(int nodesCount,
                int idx,
                //                int port,
//                ns3::NodeContainer& nodes,
                ns3::PointToPointStarHelper& p2psh,
                //                std::vector<std::pair<std::string, uint16_t>>& nodeList,
                std::vector<std::vector<uint8_t>>& serializedPublicKeys,
                std::span<const uint8_t> privateKey);

    ~ZyzaReplica() noexcept override{};

  private:
    void StartApplication() override;

  protected:
    virtual std::vector<uint8_t> processRequest(std::span<const uint8_t> request);

    void onListeningStart() override;

    void onMessage(std::span<const uint8_t> message) override;

  private:
    void processRequest(std::unique_ptr<capnp::MallocMessageBuilder> reader);

    void processProposal(proto::Proposal::Reader reader);

    void processAcknowledgement(proto::Acknowledgement::Reader reader);

    void processQuorumCertificate(capnp::MessageBuilder& builder);

    void sendToClient(const std::string& dstIp,
                      uint16_t dstPort,
                      MessageType messageType,
                      std::shared_ptr<capnp::MessageBuilder> message);

    void sendToNode(int node, MessageType messageType, capnp::MessageBuilder& message);

    void restartConnectionToNode(int i);

    bool isLeader() const;

    int nodesCount;
    int quorumSize;
    int idx;
    int currentLeader;

    //    std::vector<std::shared_ptr<uvw::tcp_handle>> activeNodeConnections;
    std::vector<ns3::Ptr<ns3::Socket>> activeNodeConnections;
    //    std::vector<std::pair<std::string, uint16_t>>& nodeList;

    std::vector<secp256k1_pubkey> publicKeys;
    uint8_t seckey[32];
    secp256k1_context* secpCtx;

    std::map<int, char[64]> pendingProposalAcks;
    std::vector<std::unique_ptr<capnp::MallocMessageBuilder>> pendingRequests;
    uint8_t proposalHash[32];

    uint8_t groupHash[32];
    uint64_t requiredQcReqId;
    capnp::MallocMessageBuilder lastQuorumCertificate;

    capnp::MallocMessageBuilder initialProposal;
    bool initPassed;
    void startNewRound();

    ns3::Time last;
    ns3::Time start;
    std::chrono::system_clock::duration sum;
    int sumCount = 0;
ns3::PointToPointStarHelper& p2psh;
//    ns3::NodeContainer& nodes;
//    std::vector<std::vector<ns3::Ipv4InterfaceContainer>>& interfaces;
};
} // namespace zyza

#endif // ZYZZYVA_A_ZYZAREPLICA_H
