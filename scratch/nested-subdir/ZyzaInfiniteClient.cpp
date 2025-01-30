#include "ZyzaInfiniteClient.h"

#include "lib/ZyzaClientRequest.h"

#include <cassert>
#include <sys/random.h>

ZyzaInfiniteClient::ZyzaInfiniteClient(int clientId,
                                       int nodesCount,
                                       std::vector<std::vector<uint8_t>>& serializedPublicKeys,
                                       ns3::PointToPointStarHelper& p2psh,
                                       std::chrono::milliseconds requestTimeout)
    : clientId(clientId),
      nodesCount(nodesCount),
      serializedPublicKeys(serializedPublicKeys),
      p2psh(p2psh),
      requestTimeout(requestTimeout),
      currentClient()
{
}

void
ZyzaInfiniteClient::StartApplication()
{
    startNextRound();
}

void
ZyzaInfiniteClient::startNextRound()
{
    roundStart = ns3::Simulator::Now();
    uint16_t leaderHint = 0xffff;
    if (currentClient != nullptr)
    {
        leaderHint = currentClient->getLeaderHint();
    }
    currentClient = std::make_unique<zyza::ZyzaClientRequest>(leaderHint,
                                                              clientId,
                                                              nodesCount,
                                                              serializedPublicKeys,
                                                              p2psh,
                                                              requestTimeout);
    assert(getrandom(message, sizeof(message), 0) == sizeof(message));
    currentClient->run(message, [this](std::vector<uint8_t> resp) {
        if (resp.size() != 2 * 128 || memcmp(message, resp.data(), 128) != 0 ||
            memcmp(message, resp.data() + 128, 128) != 0)
        {
            std::clog << "wrong response!!! request:" << std::endl;
            zyza::ZyzaCommon::hexdump(message, 128);
            std::clog << "response:" << std::endl;
            zyza::ZyzaCommon::hexdump(resp.data(), resp.size());
            exit(1);
        }
        else
        {
            auto roundEnd = ns3::Simulator::Now();
            std::clog << "client " << clientId << " got correct response in "
                      << (roundEnd - roundStart).As() << std::endl;
            startNextRound();
        }
    });
}
