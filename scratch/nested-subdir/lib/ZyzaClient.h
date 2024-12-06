#ifndef ZYZZYVA_A_ZYZACLIENT_H
#define ZYZZYVA_A_ZYZACLIENT_H

#include <cstdint>
#include <memory>
#include <secp256k1.h>
#include <span>
#include <string>
#include <uvw/tcp.h>
#include <vector>

namespace zyza {

class ZyzaClient {
public:
  ZyzaClient(int nodesCount, std::string host, int port, std::vector<std::vector<uint8_t>> publicKeys,
             std::vector<std::pair<std::string, int>> nodeList);

  std::vector<uint8_t> sendRequest(std::span<const uint8_t> request);

private:
  std::string host;
  int port;
  int nodesCount;
  int quorumSize;

  //    std::shared_ptr<uvw::tcp_handle> serverHandle;

  std::vector<secp256k1_pubkey> publicKeys;
  std::vector<std::pair<std::string, int>> nodeList;
  secp256k1_context_struct *secpCtx;
};

} // namespace zyza

#endif // ZYZZYVA_A_ZYZACLIENT_H
