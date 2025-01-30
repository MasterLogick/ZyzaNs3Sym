#ifndef ZYZZYVA_A_LIBZYZA_ENDPOINT_H
#define ZYZZYVA_A_LIBZYZA_ENDPOINT_H

#include "ns3/network-module.h"

#include <cstdint>
#include <span>

namespace zyza
{
class Endpoint
{
  public:
    explicit Endpoint(ns3::Ptr<ns3::Node> thisNode);

    void run();

    ~Endpoint();

  protected:
    virtual void onListeningStart() = 0;

    virtual void onTcpMessage(std::span<const uint8_t> message) = 0;

    virtual void onUdpMessage(std::span<const uint8_t> message) = 0;

    ns3::Ptr<ns3::Socket> serverUdpSocket;

    size_t recvStatistics = 0;
    size_t recvMsgSize = 0;

  private:
    ns3::Ptr<ns3::Node> thisNode;
    ns3::Ptr<ns3::Socket> serverTcpSocket;
    std::set<ns3::Ptr<ns3::Socket>> acceptedSockets;
    bool inDestructor;
    std::shared_ptr<int> lifetimePointer;
};
} // namespace zyza

#endif // ZYZZYVA_A_LIBZYZA_ENDPOINT_H
