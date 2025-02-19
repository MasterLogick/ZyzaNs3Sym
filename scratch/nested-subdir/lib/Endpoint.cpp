#include "Endpoint.h"

#include "ns3/internet-module.h"

#include <cstring>
#include <memory>

namespace zyza
{
struct PendingIncomingMessage
{
    size_t totalSize;
    size_t read;
    std::unique_ptr<uint8_t[]> data;
};

Endpoint::Endpoint(ns3::Ptr<ns3::Node> thisNode)
    : thisNode(thisNode),
      inDestructor(false)
{
    lifetimePointer = std::make_shared<int>();
}

void
Endpoint::run()
{
    serverTcpSocket = ns3::Socket::CreateSocket(thisNode, ns3::TcpSocketFactory::GetTypeId());
    auto l = ns3::InetSocketAddress(ns3::Ipv4Address::GetAny(), 1234);
    if (serverTcpSocket->Bind(l) == -1)
    {
        NS_FATAL_ERROR("Failed to bind socket");
    }
    if (serverTcpSocket->Listen() == -1)
    {
        NS_FATAL_ERROR("Failed to start listening on socket");
    }
    serverTcpSocket->SetAcceptCallback(
        [](auto a, auto& b) { return true; },
        [this, weakPointer = std::weak_ptr<int>(lifetimePointer)](ns3::Ptr<ns3::Socket> a,
                                                                  auto& b) -> void {
            auto s = weakPointer.lock();
            if (s == nullptr)
            {
                return;
            }
            acceptedSockets.insert(a);
            a->SetCloseCallbacks(
                [this, weakPointer = std::weak_ptr<int>(lifetimePointer)](ns3::Ptr<ns3::Socket> a) {
                    auto s = weakPointer.lock();
                    if (s == nullptr)
                    {
                        return;
                    }
                    if (inDestructor)
                    {
                        acceptedSockets.erase(a);
                    }
                },
                [this, weakPointer = std::weak_ptr<int>(lifetimePointer)](ns3::Ptr<ns3::Socket> a) {
                    auto s = weakPointer.lock();
                    if (s == nullptr)
                    {
                        return;
                    }
                    if (inDestructor)
                    {
                        acceptedSockets.erase(a);
                    }
                });
            auto pim = std::make_shared<PendingIncomingMessage>(0, 0, nullptr);
            a->SetRecvCallback([this, pim, weakPointer = std::weak_ptr<int>(lifetimePointer)](
                                   ns3::Ptr<ns3::Socket> a) -> void {
                auto p = weakPointer.lock();
                if (p == nullptr)
                {
                    return;
                }
                while (auto packet = a->Recv())
                {
                    size_t remainderSize = packet->GetSize();
                    recvStatistics += remainderSize;
                    recvMsgSize = remainderSize;
                    auto remainder = std::make_unique<uint8_t[]>(remainderSize);
                    auto* remainderPtr = remainder.get();
                    packet->CopyData(remainderPtr, remainderSize);
                    if (pim->totalSize != 0)
                    {
                        auto s = std::min<size_t>(pim->totalSize - pim->read, remainderSize);
                        memcpy(pim->data.get() + pim->read, remainderPtr, s);
                        pim->read += s;
                        if (pim->read == pim->totalSize)
                        {
                            onTcpMessage({pim->data.get(), pim->totalSize});
                            pim->data.reset();
                            pim->totalSize = 0;
                            pim->read = 0;
                            remainderPtr += s;
                            remainderSize -= s;
                        }
                        else
                        {
                            continue;
                        }
                    }
                    while (remainderSize >= 4)
                    {
                        auto nextMsgSize = *reinterpret_cast<uint32_t*>(remainderPtr);
                        if (remainderSize >= nextMsgSize)
                        {
                            onTcpMessage({reinterpret_cast<uint8_t*>(remainderPtr), nextMsgSize});
                            remainderPtr += nextMsgSize;
                            remainderSize -= nextMsgSize;
                        }
                        else
                        {
                            pim->totalSize = nextMsgSize;
                            pim->read = remainderSize;
                            pim->data.reset(new uint8_t[nextMsgSize]);
                            memcpy(pim->data.get(), remainderPtr, remainderSize);
                            break;
                        }
                    }
                }
            });
        });
    serverUdpSocket = ns3::Socket::CreateSocket(thisNode, ns3::UdpSocketFactory::GetTypeId());
    if (serverUdpSocket->Bind(ns3::InetSocketAddress(ns3::Ipv4Address::GetAny(), 1235)) == -1)
    {
        NS_FATAL_ERROR("Failed to bind socket");
    }
    serverUdpSocket->SetRecvCallback(
        [this, weakPointer = std::weak_ptr<int>(lifetimePointer)](ns3::Ptr<ns3::Socket> s) {
            auto p = weakPointer.lock();
            if (p == nullptr)
            {
                return;
            }
            while (auto packet = s->Recv())
            {
                size_t pktSize = packet->GetSize();
                recvStatistics += pktSize;
                recvMsgSize = pktSize;
                auto pktData = std::make_unique<uint8_t[]>(pktSize);
                packet->CopyData(pktData.get(), pktSize);
                auto* size = reinterpret_cast<uint32_t*>(pktData.get());
                if (*size != pktSize)
                {
                    return;
                }
                onUdpMessage({pktData.get(), pktSize});
            }
        });
    onListeningStart();
}

Endpoint::~Endpoint()
{
    inDestructor = true;
    for (const auto& item : acceptedSockets)
    {
        item->Close();
    }
    serverTcpSocket->Close();
    serverUdpSocket->Close();
}
} // namespace zyza
