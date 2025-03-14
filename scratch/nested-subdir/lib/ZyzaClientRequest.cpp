#include "ZyzaClientRequest.h"

#include "../../src/internet/model/tcp-socket-factory.h"
#include "capnp/message.h"
#include "capnp/serialize.h"
#include "lib/zyza.capnp.h"

#include "ns3/core-module.h"

#include <cassert>
#include <cstring>
#include <iostream>
#include <map>
#include <openssl/sha.h>
#include <uvw/tcp.h>

namespace zyza {
ZyzaClientRequest::ZyzaClientRequest(
    uint16_t leaderHint, int clientId, int nodesCount,
    std::vector<std::vector<uint8_t>> &serializedPublicKeys,
    ns3::PointToPointStarHelper &p2psh,
    std::chrono::milliseconds requestTimeout)
    : Endpoint(p2psh.GetSpokeNode(nodesCount + clientId)),
      ZyzaCommon(nodesCount, serializedPublicKeys), p2psh(p2psh),
      requestTimeout(requestTimeout), clientId(clientId) {
  uint8_t addr[4];
  p2psh.GetSpokeIpv4Address(nodesCount + clientId).Serialize(addr);
  host = std::to_string(addr[0]) + "." + std::to_string(addr[1]) + "." +
         std::to_string(addr[2]) + "." + std::to_string(addr[3]);
  fillRandom(&reqId, sizeof(reqId));
  if (leaderHint < nodesCount) {
    currentLeader = leaderHint;
  } else {
    currentLeader = 0xffff;
  }
}

void ZyzaClientRequest::onListeningStart() {
  if (currentLeader == 0xffff) {
    fillRandom(&currentLeader, sizeof(currentLeader));
    currentLeader %= nodesCount;
  }
  sendRequestToNode();
}

void ZyzaClientRequest::sendRequestToNode() {
  capnp::MallocMessageBuilder requestBuilder;
  auto request = requestBuilder.initRoot<proto::Request>();
  request.setImpl({req.data(), req.size()});
  request.setId(reqId);
  request.setRespAddr(host);
  request.setRespPort(1235);
  std::clog << ns3::Simulator::Now().As() << ": " << clientId
            << "c: sending request to " << currentLeader << std::endl;
  sendToNode(currentLeader, MessageType::REQUEST, requestBuilder);
  requestTimeoutTimerEvent.Cancel();
  requestTimeoutTimerEvent = ns3::Simulator::Schedule(
      ns3::Time::From(requestTimeout.count(), ns3::Time::MS), [this] {
        fillRandom(&currentLeader, sizeof(currentLeader));
        currentLeader %= nodesCount;
        sendRequestToNode();
      });
}

void ZyzaClientRequest::onTcpMessage(std::span<const uint8_t> message) {
  // client is not expected to receive tcp messages
}

void ZyzaClientRequest::onUdpMessage(std::span<const uint8_t> message) {
  auto *header = reinterpret_cast<const MessageHeader *>(message.data());
  std::clog << ns3::Simulator::Now().As() << ": " << clientId
            << "c: client got message: "
            << messageTypeToString(
                   static_cast<MessageType>(header->messageType))
            << " from " << header->senderIdx << ": " << std::hex
            << header->msgId << std::dec << std::endl;
  auto content = message.subspan<sizeof(MessageHeader)>();
  assert(header->messageSize == message.size());
  capnp::FlatArrayMessageReader responseReader(
      {reinterpret_cast<const capnp::word *>(content.data()),
       content.size() / 8});
  if (static_cast<MessageType>(header->messageType) == MessageType::RESPONSE) {
    processResponse(responseReader.getRoot<proto::Response>());
  } else if (static_cast<MessageType>(header->messageType) ==
             MessageType::REDIRECT_REQUEST) {
    processRedirect(responseReader.getRoot<proto::Redirect>());
  } else if (static_cast<MessageType>(header->messageType) ==
             MessageType::REQUEST_CANCEL) {
    processRequestCancel(responseReader.getRoot<proto::SignedMessage>());
  }
}

void ZyzaClientRequest::run(std::span<const uint8_t> request,
                            std::function<void(std::vector<uint8_t>)> rc) {
  responseCallback = rc;
  req = request;
  Endpoint::run();
}

void ZyzaClientRequest::sendToNode(int node, MessageType messageType,
                                   capnp::MessageBuilder &message) {
  uint64_t msgId = 0;
  fillRandom(&msgId, sizeof(msgId));
  uint32_t size =
      capnp::computeSerializedSizeInWords(message) * 8 + sizeof(MessageHeader);
  auto data = std::make_unique<uint8_t[]>(size);
  new (data.get()) MessageHeader(size, static_cast<uint16_t>(0xffff),
                                 static_cast<uint16_t>(messageType), msgId);
  kj::ArrayOutputStream aos(
      {data.get() + sizeof(MessageHeader), size - sizeof(MessageHeader)});
  capnp::writeMessage(aos, message);
  ns3::Address address(
      ns3::InetSocketAddress(p2psh.GetSpokeIpv4Address(node), 1235));
  std::clog << ns3::Simulator::Now().As() << ": " << clientId << "c: sending "
            << messageTypeToString(static_cast<MessageType>(messageType))
            << " to " << node << ": " << std::hex << msgId << std::dec
            << std::endl;
  serverUdpSocket->SendTo(data.get(), size, 0, address);
}

void ZyzaClientRequest::processResponse(
    const proto::Response::Reader &response) {
  if (pendingQc.contains(response.getProof().getSign().getIdx())) {
    std::clog << "duplicate response" << std::endl;
    return;
  }
  if (!verifySignedMessage(response.getProof())) {
    return;
  }
  capnp::FlatArrayMessageReader responseProofReader(
      {reinterpret_cast<const capnp::word *>(
           response.getProof().getBody().begin()),
       response.getProof().getBody().size() / 8});
  auto responseProofBody =
      responseProofReader.getRoot<proto::ResponseProofBody>();
  if (responseProofBody.getId() != reqId) {
    std::clog << "wrong request id" << std::endl;
    return;
  }
  if (responseProofBody.getProposalHash().size() != 32) {
    std::clog << "wrong proposal hash size" << std::endl;
    return;
  }
  if (responseProofBody.getImplHash().size() != 32) {
    std::clog << "wrong impl hash size" << std::endl;
    return;
  }
  uint8_t hash[32];
  SHA256(response.getImpl().begin(), response.getImpl().size(), hash);
  if (memcmp(hash, responseProofBody.getImplHash().begin(), 32) != 0) {
    std::clog << "wrong impl hash" << std::endl;
    return;
  }
  uint8_t proofHash[32];
  SHA256(response.getProof().getBody().begin(),
         response.getProof().getBody().size(), proofHash);
  auto &resp = pendingQc[response.getProof().getSign().getIdx()];
  memcpy(resp.proofHash, proofHash, 32);
  memcpy(resp.sign, response.getProof().getSign().getSign().begin(), 64);
  int c = 0;
  for (const auto &[nodeId, r] : pendingQc) {
    if (memcmp(r.proofHash, proofHash, 32) == 0) {
      c++;
    }
  }
  if (c == quorumSize) {
    capnp::MallocMessageBuilder clientResponseBuilder;
    auto clientResponse =
        clientResponseBuilder.initRoot<proto::ClientResponse>();
    clientResponse.setId(reqId);
    auto completed = clientResponse.initCompleted();
    completed.setProofBody(response.getProof().getBody());
    auto proof = completed.initProof(quorumSize);
    int i = 0;
    for (const auto &[nodeId, r] : pendingQc) {
      if (memcmp(r.proofHash, proofHash, 32) == 0) {
        proof[i].setIdx(nodeId);
        proof[i].setSign({r.sign, 64});
        i++;
      }
    }

    for (int j = 0; j < nodesCount; ++j) {
      sendToNode(j, MessageType::CLIENT_RESPONSE, clientResponseBuilder);
    }
    std::vector<uint8_t> r(response.getImpl().begin(),
                           response.getImpl().end());
    requestTimeoutTimerEvent.Cancel();
    pendingQc.clear();
    cancelRequests.clear();
    responseCallback(std::move(r));
  }
}

void ZyzaClientRequest::processRedirect(
    const proto::Redirect::Reader &redirect) {
  if (redirect.getRedirect() >= nodesCount) {
    std::clog << "wrong redirect node idx" << std::endl;
    return;
  }
  currentLeader = redirect.getRedirect();
  std::clog << clientId << "c: resending request to " << currentLeader
            << std::endl;
  sendRequestToNode();
}
void ZyzaClientRequest::processRequestCancel(
    const proto::SignedMessage::Reader &signedMessage) {
  if (!verifySignedMessage(signedMessage)) {
    return;
  }
  capnp::FlatArrayMessageReader requestCancelBodyReader(
      {reinterpret_cast<const capnp::word *>(signedMessage.getBody().begin()),
       signedMessage.getBody().size() / 8});
  auto requestCancelBody =
      requestCancelBodyReader.getRoot<proto::RequestCancelBody>();
  if (requestCancelBody.getId() != reqId) {
    std::clog << "wrong request cancel request id" << std::endl;
    return;
  }
  memcpy(cancelRequests[requestCancelBody.getBackupLeader()]
                       [signedMessage.getSign().getIdx()],
         signedMessage.getSign().getSign().begin(), 64);
  if (cancelRequests[requestCancelBody.getBackupLeader()].size() ==
      quorumSize) {
    capnp::MallocMessageBuilder clientResponseBuilder;
    auto clientResponse =
        clientResponseBuilder.initRoot<proto::ClientResponse>();
    clientResponse.setId(reqId);
    auto canceled = clientResponse.initCanceled();
    canceled.setBackupLeader(requestCancelBody.getBackupLeader());
    auto proof = canceled.initProof(quorumSize);
    int i = 0;
    for (const auto &[nodeId, sign] :
         cancelRequests[requestCancelBody.getBackupLeader()]) {
      proof[i].setIdx(nodeId);
      proof[i].setSign({sign, 64});
      i++;
    }
    for (int j = 0; j < nodesCount; ++j) {
      sendToNode(j, MessageType::CLIENT_RESPONSE, clientResponseBuilder);
    }
    cancelRequests.clear();
    pendingQc.clear();
    fillRandom(&reqId, sizeof(reqId));
    fillRandom(&currentLeader, sizeof(currentLeader));
    sendRequestToNode();
  }
}
} // namespace zyza
