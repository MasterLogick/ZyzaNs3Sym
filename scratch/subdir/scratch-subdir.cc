/*
 * SPDX-License-Identifier: GPL-2.0-only
 */

// This example shows how to create new simulations that are implemented in
// multiple files and headers. The structure of this simulation project
// is as follows:
//
// scratch/
// |  subdir/
// |  |  - scratch-subdir.cc                   // Main simulation file
// |  |  - scratch-subdir-additional-header.h  // Additional header
// |  |  - scratch-subdir-additional-header.cc // Additional header implementation
//
// This file contains the main() function, which calls an external function
// defined in the "scratch-subdir-additional-header.h" header file and
// implemented in "scratch-subdir-additional-header.cc".

#include "../../src/applications/helper/packet-sink-helper.h"
#include "../../src/applications/helper/udp-echo-helper.h"
#include "../../src/csma/helper/csma-helper.h"
#include "../../src/internet/helper/internet-stack-helper.h"
#include "../../src/internet/helper/ipv4-address-helper.h"
#include "../../src/internet/helper/ipv4-global-routing-helper.h"
#include "../../src/network/helper/node-container.h"
#include "../../src/network/utils/error-model.h"
#include "../../src/point-to-point/helper/point-to-point-helper.h"
#include "scratch-subdir-additional-header.h"

#include "ns3/core-module.h"
#include "ns3/tcp-socket-factory.h"

#include <string>

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("ScratchSubdir");

int
main(int argc, char* argv[])
{
    LogComponentEnable("TutorialApp", LOG_LEVEL_ALL);

    //    LogComponentEnable("UdpEchoClientApplication", LOG_LEVEL_INFO);
    //    LogComponentEnable("UdpEchoServerApplication", LOG_LEVEL_INFO);

    // In the following three lines, TCP NewReno is used as the congestion
    // control algorithm, the initial congestion window of a TCP connection is
    // set to 1 packet, and the classic fast recovery algorithm is used. Note
    // that this configuration is used only to demonstrate how TCP parameters
    // can be configured in ns-3. Otherwise, it is recommended to use the default
    // settings of TCP in ns-3.
    Config::SetDefault("ns3::TcpL4Protocol::SocketType", StringValue("ns3::TcpNewReno"));
    Config::SetDefault("ns3::TcpSocket::InitialCwnd", UintegerValue(1));
    Config::SetDefault("ns3::TcpL4Protocol::RecoveryType",
                       TypeIdValue(TypeId::LookupByName("ns3::TcpClassicRecovery")));

    NodeContainer nodes;
    nodes.Create(2);

    PointToPointHelper pointToPoint;
    pointToPoint.SetDeviceAttribute("DataRate", StringValue("5Mbps"));
    pointToPoint.SetChannelAttribute("Delay", StringValue("2ms"));

    NetDeviceContainer devices;
    devices = pointToPoint.Install(nodes);

    Ptr<RateErrorModel> em = CreateObject<RateErrorModel>();
    em->SetAttribute("ErrorRate", DoubleValue(0.00001));
    devices.Get(1)->SetAttribute("ReceiveErrorModel", PointerValue(em));

    InternetStackHelper stack;
    stack.Install(nodes);

    Ipv4AddressHelper address;
    address.SetBase("10.1.1.0", "255.255.255.252");
    Ipv4InterfaceContainer interfaces = address.Assign(devices);

    uint16_t sinkPort = 8080;
    Address sinkAddress(InetSocketAddress(interfaces.GetAddress(1), sinkPort));
    PacketSinkHelper packetSinkHelper("ns3::TcpSocketFactory",
                                      InetSocketAddress(Ipv4Address::GetAny(), sinkPort));
    ApplicationContainer sinkApps = packetSinkHelper.Install(nodes.Get(1));
    sinkApps.Start(Seconds(0.));
    sinkApps.Stop(Seconds(20.));

    Ptr<Socket> ns3TcpSocket = Socket::CreateSocket(nodes.Get(0), TcpSocketFactory::GetTypeId());
    //    ns3TcpSocket->TraceConnectWithoutContext("CongestionWindow", MakeCallback(&CwndChange));

    Ptr<TutorialApp> app = CreateObject<TutorialApp>();
    app->Setup(ns3TcpSocket, sinkAddress, 1040, 1000, DataRate("1Mbps"));
    nodes.Get(0)->AddApplication(app);
    app->SetStartTime(Seconds(1.));
    app->SetStopTime(Seconds(20.));

    //    devices.Get(1)->TraceConnectWithoutContext("PhyRxDrop", MakeCallback(&RxDrop));

    Simulator::Stop(Seconds(20));
    Simulator::Run();
    Simulator::Destroy();

    //    return 0;
}
