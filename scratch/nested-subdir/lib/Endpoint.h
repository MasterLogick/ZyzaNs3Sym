#ifndef ZYZZYVA_A_LIBZYZA_ENDPOINT_H
#define ZYZZYVA_A_LIBZYZA_ENDPOINT_H

#include <cstdint>
#include <span>
// #include <uvw/loop.h>
// #include <uvw/tcp.h>
#include "ns3/network-module.h"

namespace zyza
{
class Endpoint
{
  public:
    explicit Endpoint(ns3::Ptr<ns3::Node> thisNode);

    void run();

  protected:
    virtual void onListeningStart() = 0;
    virtual void onMessage(std::span<const uint8_t> message) = 0;

    //  std::shared_ptr<uvw::loop> loop;
    //  std::shared_ptr<uvw::tcp_handle> serverSocket;

  private:
    ns3::Ptr<ns3::Node> thisNode;
};
} // namespace zyza

#endif // ZYZZYVA_A_LIBZYZA_ENDPOINT_H
