#include "Endpoint.h"
// #include <uvw/loop.h>
// #include <uvw/tcp.h>

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
    : thisNode(thisNode)
{
}

void
Endpoint::run()
{
    auto m_socket = ns3::Socket::CreateSocket(thisNode, ns3::TcpSocketFactory::GetTypeId());
    auto l = ns3::InetSocketAddress(ns3::Ipv4Address::GetAny(), 1234);
    if (m_socket->Bind(l) == -1)
    {
        NS_FATAL_ERROR("Failed to bind socket");
    }
    m_socket->Listen();
    m_socket->SetAcceptCallback(
        [](auto a, auto& b) { return true; },
        [this](ns3::Ptr<ns3::Socket> a, auto& b) -> void {
            auto pim = new PendingIncomingMessage();

            a->SetRecvCallback([this, pim](ns3::Ptr<ns3::Socket> a) -> void {
                while (auto packet = a->Recv())
                {
                    size_t remainderSize = packet->GetSize();
                    auto remainder = std::make_unique<uint8_t[]>(remainderSize);
                    uint8_t* remainderPtr = remainder.get();
                    packet->CopyData(remainderPtr, remainderSize);
                    if (pim->totalSize != 0)
                    {
                        auto s = std::min<size_t>(pim->totalSize - pim->read, remainderSize);
                        memcpy(pim->data.get() + pim->read, remainderPtr, s);
                        pim->read += s;
                        if (pim->read == pim->totalSize)
                        {
                            onMessage({pim->data.get(), pim->totalSize});
                            remainderPtr += s;
                            remainderSize -= s;
                        }
                        else
                        {
                            return;
                        }
                    }
                    while (remainderSize >= 4)
                    {
                        auto nextMsgSize = *reinterpret_cast<uint32_t*>(remainderPtr);
                        if (remainderSize >= nextMsgSize)
                        {
                            onMessage({reinterpret_cast<uint8_t*>(remainderPtr), nextMsgSize});
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
    //    loop = uvw::loop::create();
    //    serverSocket = loop->resource<uvw::tcp_handle>();
//    serverSocket->on<uvw::listen_event>([this](const uvw::listen_event&, uvw::tcp_handle& srv) {
//        std::shared_ptr<uvw::tcp_handle> client = srv.parent().resource<uvw::tcp_handle>();
//        client->data(std::make_shared<PendingIncomingMessage>(0, 0, nullptr));
//        client->on<uvw::data_event>([this](const uvw::data_event& event, uvw::tcp_handle& h) {
//
//        });
//        serverSocket->accept(*client);
//        client->read();
//    });
//    serverSocket->bind("0.0.0.0", port);
//    serverSocket->listen();

    onListeningStart();
//    loop->run();
}
} // namespace zyza
