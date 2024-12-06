#include "ZyzaClientRequest.h"
#include "capnp/message.h"
#include "capnp/serialize.h"
#include "lib/zyza.capnp.h"
#include <cassert>
#include <cstring>
#include <iostream>
#include <map>
#include <openssl/sha.h>
#include <sys/random.h>
#include <uvw.hpp>
#include <uvw/tcp.h>

namespace zyza {
ZyzaClientRequest::ZyzaClientRequest(std::string host, int nodesCount, int currentLeader,
                                     std::vector<std::vector<uint8_t>> &serializedPublicKeys,
                                     std::vector<std::pair<std::string, uint16_t>> &nodeList)
    : Endpoint(0), host(std::move(host)), nodesCount(nodesCount), quorumSize((nodesCount + 2) / 3 + 1),
      nodeList(nodeList) {
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
  ssize_t rc = getrandom(&id, 8, 0);
  assert(rc == 8);
}

void ZyzaClientRequest::onListeningStart() {
//  uint16_t port = serverSocket->sock().port;
  auto requestBuilder = std::make_shared<capnp::MallocMessageBuilder>();
  auto request = requestBuilder->initRoot<proto::Request>();
  request.setId(id);
  request.setRespAddr(host);
//  request.setRespPort(port);
  request.setImpl({req.data(), req.size()});
  sendToNode(currentLeader, MessageType::MESSAGE_TYPE_REQUEST, requestBuilder);
}

void ZyzaClientRequest::onMessage(std::span<const uint8_t> message) {
  auto *header = reinterpret_cast<const MessageHeader *>(message.data());
  auto content = message.subspan<sizeof(MessageHeader)>();
  assert(header->messageSize == message.size());
  if (static_cast<MessageType>(header->messageType) == MessageType::MESSAGE_TYPE_RESPONSE) {
    auto responseBuilder = std::make_unique<capnp::MallocMessageBuilder>();
    capnp::initMessageBuilderFromFlatArrayCopy(
        {reinterpret_cast<const capnp::word *>(content.data()), content.size() / 8}, *responseBuilder);
    auto response = responseBuilder->getRoot<proto::Response>();
    capnp::FlatArrayMessageReader responseBodyBuilder(
        {reinterpret_cast<capnp::word *>(response.getBody().begin()), response.getBody().size() / 8});
    auto responseBody = responseBodyBuilder.getRoot<proto::ResponseBody>();
    if (responseBody.getId() != id) {
      return;
    }
    if (response.getSign().getSign().size() != 64) {
      return;
    }
    if (responseBody.getProposalHash().size() != 64) {
      return;
    }
    capnp::MallocMessageBuilder b;
    b.setRoot(response.getBody().asReader());
    auto data = capnp::messageToFlatArray(b);
    uint8_t hash[32];
    SHA256(data.asBytes().begin(), data.asBytes().size(), hash);
    secp256k1_ecdsa_signature sig;
    int rc = secp256k1_ecdsa_signature_parse_compact(secpCtx, &sig, response.getSign().getSign().begin());
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
//      loop->walk([](auto &handle) { handle.close(); });
//      for (int j = 0; j < nodeList.size(); ++j) {
//        sendToNode(j, MessageType::MESSAGE_TYPE_QC, qcBuilder);
//      }
//      loop->run();
    }
  }
}

std::vector<uint8_t> ZyzaClientRequest::run(std::span<const uint8_t> request) {
  req = request;
  try {
    Endpoint::run();
  } catch (std::exception &e) {
    std::cout << e.what() << std::endl;
  }
  return std::move(resp);
}

void ZyzaClientRequest::sendToNode(int node, MessageType messageType, std::shared_ptr<capnp::MessageBuilder> message) {
//  auto cl = loop->resource<uvw::tcp_handle>();
//  cl->on<uvw::connect_event>([message, messageType](uvw::connect_event &, uvw::tcp_handle &h) {
//    std::cout << "connected to leader" << std::endl;
//    MessageHeader header{
//        static_cast<uint32_t>(capnp::computeSerializedSizeInWords(*message) * 8 + sizeof(MessageHeader)),
//        static_cast<uint16_t>(0xffff), static_cast<uint16_t>(messageType)};
//    auto rc = h.try_write(reinterpret_cast<char *>(&header), sizeof(MessageHeader));
//    assert(rc == sizeof(MessageHeader));
//    capnp::writeMessageToFd(h.fd(), *message);
//    h.close();
//  });
//  cl->connect(nodeList[node].first, nodeList[node].second);
}
} // namespace zyza