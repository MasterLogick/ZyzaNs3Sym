#ifndef ZYZZYVA_A_ZYZACLIENTREQUEST_H
#define ZYZZYVA_A_ZYZACLIENTREQUEST_H

#include "../../../src/point-to-point-layout/model/point-to-point-star.h"
#include "Endpoint.h"
#include "MessageHeader.h"
#include "ZyzaCommon.h"
#include "capnp/message.h"
#include "lib/zyza.capnp.h"

#include <chrono>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <secp256k1.h>
#include <span>
#include <string>
#include <vector>

namespace zyza
{
class ZyzaClientRequest : private Endpoint, private ZyzaCommon
{
  public:
    ZyzaClientRequest(uint16_t leaderHint,
                      int clientId,
                      int nodesCount,
                      std::vector<std::vector<uint8_t>>& publicKeys,
                      ns3::PointToPointStarHelper& p2psh,
                      std::chrono::milliseconds requestTimeout);

    void run(std::span<const uint8_t> request,
             std::function<void(std::vector<uint8_t>)> responseCallback);

    uint16_t getLeaderHint() const
    {
        return currentLeader;
    }

  protected:
    void onListeningStart() override;

    void onTcpMessage(std::span<const uint8_t> message) override;

  private:
    void onUdpMessage(std::span<const uint8_t> message) override;

  private:
    void sendToNode(int node,
                    MessageType messageType,
                    std::shared_ptr<capnp::MessageBuilder> message);

    void sendRequestToNode(uint16_t i);

    void processResponse(const proto::Response::Reader& response);

    void processRedirect(const proto::Redirect::Reader& redirect);

    void processQuorumDropRequest(const proto::QuorumDropRequest::Reader& qdr, int sender);

    std::string host;
    uint64_t reqId;
    int clientId;
    ns3::PointToPointStarHelper& p2psh;
    std::span<const uint8_t> req;
    uint8_t dropSecret[32];
    std::chrono::milliseconds requestTimeout;
    std::function<void(std::vector<uint8_t>)> responseCallback;

    uint16_t currentLeader;
    std::vector<uint8_t> resp;
    std::map<int, std::pair<uint8_t[64], uint8_t[32]>> pendingQc;
    ns3::EventId requestTimeoutTimerEvent;
};
} // namespace zyza

#endif // ZYZZYVA_A_ZYZACLIENTREQUEST_H
