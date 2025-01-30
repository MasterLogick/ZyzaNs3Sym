#ifndef NS3_ZYZAINFINITECLIENT_H
#define NS3_ZYZAINFINITECLIENT_H

#include "../../src/point-to-point-layout/model/point-to-point-star.h"
#include "lib/ZyzaClientRequest.h"

#include "ns3/application.h"

#include <chrono>

class ZyzaInfiniteClient : public ns3::Application
{
  public:
    ZyzaInfiniteClient(int clientId,
                       int nodesCount,
                       std::vector<std::vector<uint8_t>>& serializedPublicKeys,
                       ns3::PointToPointStarHelper& p2psh,
                       std::chrono::milliseconds requestTimeout);

  private:
    void StartApplication() override;

    void startNextRound();

    int clientId;
    int nodesCount;
    std::vector<std::vector<uint8_t>>& serializedPublicKeys;
    ns3::PointToPointStarHelper& p2psh;
    std::chrono::milliseconds requestTimeout;
    uint8_t message[128];
    std::unique_ptr<zyza::ZyzaClientRequest> currentClient;
    ns3::Time roundStart;
};

#endif // NS3_ZYZAINFINITECLIENT_H
