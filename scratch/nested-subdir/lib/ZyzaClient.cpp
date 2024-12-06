#include "ZyzaClient.h"
#include "capnp/message.h"
#include "capnp/serialize.h"
#include "zyza.capnp.h"
#include <cassert>
#include <cstring>
#include <map>
#include <openssl/sha.h>
#include <sys/random.h>
#include <uvw.hpp>
#include <uvw/tcp.h>

namespace zyza {
ZyzaClient::ZyzaClient(int nodesCount, std::string host, int port,
                       std::vector<std::vector<uint8_t>> serializedPublicKeys,
                       std::vector<std::pair<std::string, int>> nodeList)
    : nodesCount(nodesCount), quorumSize((nodesCount + 2) / 3 + 1), nodeList(std::move(nodeList)) {
  assert(this->nodeList.size() == nodesCount);
  secpCtx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
  uint8_t seed[32];
  ssize_t res = getrandom(seed, 32, 0);
  assert(res == 32);
  assert(secp256k1_context_randomize(secpCtx, seed));
  for (size_t i = 0; i < publicKeys.size(); i++) {
    auto rc = secp256k1_ec_pubkey_parse(secpCtx, &publicKeys[i], serializedPublicKeys[i].data(),
                                        serializedPublicKeys[i].size());
    assert(rc);
  }
}

struct PendingIncomingMessage {
  size_t totalSize;
  size_t read;
  std::unique_ptr<uint8_t[]> data;
};

struct MessageHeader {
  uint32_t messageSize;
  uint16_t senderIdx;
  uint16_t messageType;
};

#define MESSAGE_TYPE_REQUEST 1
#define MESSAGE_TYPE_RESPONSE 2
#define MESSAGE_TYPE_PROPOSAL 3
#define MESSAGE_TYPE_ACK 4
#define MESSAGE_TYPE_QC 5
#define MESSAGE_TYPE_REDIRECT 6

std::vector<uint8_t> ZyzaClient::sendRequest(std::span<const uint8_t> request) {
  auto loop = uvw::loop::create();
  std::map<int, std::pair<std::unique_ptr<capnp::MallocMessageBuilder>, uint8_t[32]>> pendingQc;
  uint64_t id = 0;
  ssize_t rc = getrandom(&id, 8, 0);
  assert(rc == 8);
  auto serverHandle = loop->resource<uvw::tcp_handle>();
  serverHandle->bind(host, 0);
  auto realPort = serverHandle->sock().port;
  std::vector<uint8_t> resp;
  auto processMessage = [&](std::span<const uint8_t> message) {
    auto *header = reinterpret_cast<const MessageHeader *>(message.data());
    auto content = message.subspan<sizeof(MessageHeader)>();
    assert(header->messageSize == message.size());
    if (header->messageType == MESSAGE_TYPE_RESPONSE) {
      auto responseBuilder = std::make_unique<capnp::MallocMessageBuilder>();
      capnp::initMessageBuilderFromFlatArrayCopy(
          {reinterpret_cast<const capnp::word *>(content.data()), content.size() / 8}, *responseBuilder);
      auto response = responseBuilder->getRoot<proto::Response>();
      if (response.getBody().getId() != id) {
        return;
      }
      if (response.getSign().getSign().size() != 64) {
        return;
      }
      if (response.getBody().getProposalHash().size() != 64) {
        return;
      }
      capnp::MallocMessageBuilder b;
      b.setRoot(response.getBody().asReader());
      auto data = capnp::messageToFlatArray(b);
      uint8_t hash[32];
      SHA256(data.asBytes().begin(), data.asBytes().size(), hash);
      secp256k1_ecdsa_signature sig;
      rc = secp256k1_ecdsa_signature_parse_compact(secpCtx, &sig, response.getSign().getSign().begin());
      if (!rc) {
        return;
      }
      rc = secp256k1_ecdsa_verify(secpCtx, &sig, hash, &publicKeys[response.getSign().getIdx()]);
      if (!rc) {
        return;
      }
      pendingQc[response.getSign().getIdx()].first = std::move(responseBuilder);
      memcpy(pendingQc[response.getSign().getIdx()].second, hash, 32);
      int c = 0;
      for (const auto &item : pendingQc) {
        if (memcmp(item.second.second, hash, 32) == 0) {
          c++;
        }
      }
      if (c == quorumSize) {
        resp.assign(b.getRoot<proto::ResponseBody>().getImpl().begin(),
                    b.getRoot<proto::ResponseBody>().getImpl().end());
        auto qcBuilder = std::make_shared<capnp::MallocMessageBuilder>();
        auto qc = qcBuilder->initRoot<proto::QuorumCertificate>();
        qc.adoptResponse(b.getOrphanage().newOrphan<proto::ResponseBody>());
        auto signs = qc.initSigns(quorumSize);
        int i = 0;
        for (const auto &item : pendingQc) {
          if (memcmp(item.second.second, hash, 32) == 0) {
            signs.setWithCaveats(i, item.second.first->getRoot<proto::Response>().getSign());
          }
        }
        loop->walk([](auto &handle) { handle.close(); });
        for (const auto &[hst, prt] : nodeList) {
          auto cl = loop->resource<uvw::tcp_handle>();
          cl->on<uvw::connect_event>([qcBuilder](uvw::connect_event &, uvw::tcp_handle &h) {
            MessageHeader header{
                static_cast<uint32_t>(capnp::computeSerializedSizeInWords(*qcBuilder) * 8 + sizeof(MessageHeader)),
                static_cast<uint16_t>(0xffff), MESSAGE_TYPE_QC};
            auto rc = h.try_write(reinterpret_cast<char *>(&header), sizeof(MessageHeader));
            assert(rc == sizeof(MessageHeader));
            capnp::writeMessageToFd(h.fd(), *qcBuilder);
            h.close();
          });
          cl->connect(hst, prt);
        }
      }
    }
  };
  serverHandle->on<uvw::listen_event>([&](uvw::listen_event &, uvw::tcp_handle &h) {
    auto connection = uvw::loop::get_default()->resource<uvw::tcp_handle>();
    connection->data(std::make_shared<PendingIncomingMessage>(0, 0, nullptr));
    connection->on<uvw::data_event>([&](uvw::data_event &event, uvw::tcp_handle &) {
      auto pim = h.data<PendingIncomingMessage>();
      auto *remainderPtr = event.data.get();
      size_t remainderSize = event.length;
      if (pim->totalSize != 0) {
        auto s = std::min<size_t>(pim->totalSize - pim->read, event.length);
        memcpy(pim->data.get() + pim->read, event.data.get(), s);
        pim->read += s;
        if (pim->read == pim->totalSize) {
          processMessage({pim->data.get(), pim->totalSize});
          remainderPtr += s;
          remainderSize -= s;
        } else {
          return;
        }
      }
      while (remainderSize >= 4) {
        auto nextMsgSize = *reinterpret_cast<uint32_t *>(remainderPtr);
        if (remainderSize >= nextMsgSize) {
          processMessage({reinterpret_cast<uint8_t *>(remainderPtr), nextMsgSize});
          remainderPtr += nextMsgSize;
          remainderSize -= nextMsgSize;
        } else {
          pim->totalSize = nextMsgSize;
          pim->read = remainderSize;
          pim->data.reset(new uint8_t[nextMsgSize]);
          memcpy(pim->data.get(), remainderPtr, remainderSize);
          break;
        }
      }
    });
    h.accept(*connection);
  });
  serverHandle->listen();
  loop->run();
  return resp;
}
} // namespace zyza