#include "ZyzaCommon.h"

#include <algorithm>
#include <capnp/serialize.h>
#include <cassert>
#include <iostream>
#include <openssl/sha.h>
#include <random>
#include <sstream>

namespace zyza {
void ZyzaCommon::hexdump(const uint8_t *arr, const char *note) {
  std::stringstream ss;
  for (int i = 0; i < 32; ++i) {
    ss << std::hex << (int)arr[i];
  }
  std::clog << note << ": " << ss.str() << std::endl;
}

void ZyzaCommon::hexdump(const void *arr, size_t size) {
  const auto *ptr = reinterpret_cast<const uint8_t *>(arr);
  std::clog << std::hex;
  for (size_t i = 0; i < size; ++i) {
    std::clog << (int)ptr[i];
  }
  std::clog << std::dec << std::endl;
}

static std::mt19937_64 engine;

void ZyzaCommon::fillRandom(void *data, size_t size) {
  auto *d = static_cast<uint64_t *>(data);
  while (size >= 8) {
    *d = engine();
    size -= 8;
    d++;
  }
  if (size > 0) {
    auto val = engine();
    memcpy(static_cast<void *>(d), &val, size);
  }
}

ZyzaCommon::ZyzaCommon(int nodesCount,
                       std::vector<std::vector<uint8_t>> &serializedPublicKeys)
    : nodesCount(nodesCount), quorumSize(nodesCount - nodesCount / 3),
      publicKeys(nodesCount) {
  for (size_t i = 0; i < publicKeys.size(); i++) {
    auto rc = secp256k1_ec_pubkey_parse(
        secp256k1_context_static, &publicKeys[i],
        serializedPublicKeys[i].data(), serializedPublicKeys[i].size());
    assert(rc);
  }
}

bool ZyzaCommon::verifyData(const capnp::AnyPointer::Reader &data,
                            const proto::Signature::Reader &signature) {
  if (signature.getIdx() >= nodesCount) {
    std::clog << "wrong signer idx" << std::endl;
    return false;
  }
  if (signature.getSign().size() != 64) {
    std::clog << "wrong signature size" << std::endl;
  }
  uint8_t hash[32];
  hashStruct(data, hash);
  return verifyData(hash, signature.getSign().begin(), signature.getIdx());
}

bool ZyzaCommon::verifySignedMessage(
    const proto::SignedMessage<capnp::AnyPointer>::Reader &signedMessage) {
  return verifyData(signedMessage.getBody(), signedMessage.getSign());
}

bool ZyzaCommon::verifyData(const uint8_t *hash, const uint8_t *sign,
                            int signer) {
  secp256k1_ecdsa_signature sig;
  int rc = secp256k1_ecdsa_signature_parse_compact(secp256k1_context_static,
                                                   &sig, sign);
  if (rc != 1) {
    std::clog << "wrong packed sign" << std::endl;
    return false;
  }
  rc = secp256k1_ecdsa_verify(secp256k1_context_static, &sig, hash,
                              &publicKeys[signer]);
  if (rc != 1) {
    std::clog << "wrong proposal sign" << std::endl;
    return false;
  }
  return true;
}

void ZyzaCommon::hexdump(const capnp::AnyPointer::Reader &message,
                         const char *note) {
  uint8_t hash[32];
  hashStruct(message, hash);
  hexdump(hash, note);
}

void ZyzaCommon::hexdump(const capnp::AnyStruct::Reader &message,
                         const char *note) {
  uint8_t hash[32];
  hashStruct(message, hash);
  hexdump(hash, note);
}

void ZyzaCommon::hashStruct(const capnp::AnyPointer::Reader &data,
                            std::span<uint8_t, 32> hash32) {
  capnp::MallocMessageBuilder builder;
  builder.setRoot(data);
  auto flatBody = capnp::messageToFlatArray(builder);
  SHA256(flatBody.asBytes().begin(), flatBody.asBytes().size(), hash32.data());
}
void ZyzaCommon::hashStruct(const capnp::AnyStruct::Reader &data,
                            std::span<uint8_t, 32> hash32) {
  capnp::MallocMessageBuilder builder;
  builder.setRoot(data);
  auto flatBody = capnp::messageToFlatArray(builder);
  SHA256(flatBody.asBytes().begin(), flatBody.asBytes().size(), hash32.data());
}
} // namespace zyza