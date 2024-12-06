#ifndef ZYZZYVA_A_ZYZACLIENTREQUEST_H
#define ZYZZYVA_A_ZYZACLIENTREQUEST_H

#include "Endpoint.h"
#include "MessageHeader.h"
#include "capnp/message.h"
#include <cstdint>
#include <map>
#include <memory>
#include <secp256k1.h>
#include <span>
#include <string>
#include <uvw/tcp.h>
#include <vector>

namespace zyza {
class ZyzaClientRequest : private Endpoint {
public:
  ZyzaClientRequest(std::string host, int nodesCount, int currentLeader, std::vector<std::vector<uint8_t>> &publicKeys,
                    std::vector<std::pair<std::string, uint16_t>> &nodeList);

  std::vector<uint8_t> run(std::span<const uint8_t> request);

protected:
  void onListeningStart() override;

  void onMessage(std::span<const uint8_t> message) override;

private:
  void sendToNode(int node, MessageType messageType, std::shared_ptr<capnp::MessageBuilder> message);

  std::string host;
  int nodesCount;
  int quorumSize;
  int currentLeader;
  std::span<const uint8_t> req;
  std::vector<uint8_t> resp;
  std::map<int, std::pair<std::unique_ptr<capnp::MallocMessageBuilder>, uint8_t[32]>> pendingQc;
  uint64_t id;
  std::vector<secp256k1_pubkey> publicKeys;
  std::vector<std::pair<std::string, uint16_t>> &nodeList;
  secp256k1_context_struct *secpCtx;
};
} // namespace zyza

#endif // ZYZZYVA_A_ZYZACLIENTREQUEST_H
