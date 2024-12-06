/*
 * SPDX-License-Identifier: GPL-2.0-only
 */

// This example shows how to create new simulations that are implemented in
// multiple files and headers. The structure of this simulation project
// is as follows:
//
// scratch/
// |  nested-subdir/
// |  |  - scratch-nested-subdir-executable.cc        // Main simulation file
// |  |  lib
// |  |  |  - scratch-nested-subdir-library-header.h  // Additional header
// |  |  |  - scratch-nested-subdir-library-source.cc // Additional header implementation
//
// This file contains the main() function, which calls an external function
// defined in the "scratch-nested-subdir-library-header.h" header file and
// implemented in "scratch-nested-subdir-library-source.cc".

#include "../../src/point-to-point-layout/model/point-to-point-star.h"
#include "lib/ZyzaReplica.h"

#include "ns3/applications-module.h"
#include "ns3/core-module.h"
#include "ns3/csma-module.h"
#include "ns3/internet-module.h"
#include "ns3/network-module.h"
#include "ns3/point-to-point-module.h"

#include <cassert>
#include <string>
#include <sys/random.h>

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("ScratchNestedSubdir");

int
main(int argc, char* argv[])
{
    LogComponentEnable("ZyzaReplica", LOG_LEVEL_INFO);
//        LogComponentEnable("ZyzaReplica", LOG_LEVEL_DEBUG);
    int n = 100;
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

    PointToPointHelper pointToPoint;
    pointToPoint.SetDeviceAttribute("DataRate", StringValue("100Mbps"));
    pointToPoint.SetChannelAttribute("Delay", TimeValue(MilliSeconds(100)));
    PointToPointStarHelper p2psh(n, pointToPoint);
    /*NodeContainer nodes;
    nodes.Create(n);

    PointToPointHelper pointToPoint;
    pointToPoint.SetDeviceAttribute("DataRate", StringValue("100Mbps"));
    pointToPoint.SetChannelAttribute("Delay", TimeValue(MilliSeconds(200)));
    std::vector<std::vector<ns3::NetDeviceContainer>> netDevContainers(n);
    for (int i = 0; i < n; ++i)
    {
        auto& cont = netDevContainers[i];
        for (int j = i; j < n; ++j)
        {
            auto netDevCont = pointToPoint.Install(nodes.Get(i), nodes.Get(j));
            cont.push_back(netDevCont);
        }
    }*/
    std::clog << "created net devices" << std::endl;
    //    CsmaHelper csma;
    //    csma.SetChannelAttribute("DataRate", StringValue("1000Mbps"));
    //    csma.SetChannelAttribute("Delay", TimeValue(MilliSeconds(2)));

    //    NetDeviceContainer csmaDevices;
    //    csmaDevices = csma.Install(nodes);

    //    PointToPointHelper pointToPoint;
    //    pointToPoint.SetDeviceAttribute("DataRate", StringValue("5Mbps"));
    //    pointToPoint.SetChannelAttribute("Delay", StringValue("2ms"));

    //    Ptr<RateErrorModel> em = CreateObject<RateErrorModel>();
    //    em->SetAttribute("ErrorRate", DoubleValue(0.00001));
    //    devices.Get(1)->SetAttribute("ReceiveErrorModel", PointerValue(em));

    InternetStackHelper stack;
    p2psh.InstallStack(stack);
    //    stack.Install(nodes);

    Ipv4AddressHelper addressHelper;
    addressHelper.SetBase("1.0.0.0", "255.255.255.252");
    p2psh.AssignIpv4Addresses(addressHelper);
    /*std::vector<std::vector<ns3::Ipv4InterfaceContainer>> ifContainers(n);

    for (int i = 0; i < n; ++i)
    {
        auto& cont = ifContainers[i];
        for (int j = i; j < n; ++j)
        {
            cont.push_back(addressHelper.Assign(netDevContainers[i][j - i]));
            addressHelper.NewNetwork();
        }
    }*/
    std::clog << "assigned net addresses" << std::endl;
    //    Ipv4InterfaceContainer interfaces = address.Assign(csmaDevices);

    //    uint16_t sinkPort = 8080;
    //    Address sinkAddress(InetSocketAddress(interfaces.GetAddress(1), sinkPort));
    //    PacketSinkHelper packetSinkHelper("ns3::TcpSocketFactory",
    //                                      InetSocketAddress(Ipv4Address::GetAny(), sinkPort));
    //    ApplicationContainer sinkApps = packetSinkHelper.Install(nodes.Get(1));
    //    sinkApps.Start(Seconds(0.));
    //    sinkApps.Stop(Seconds(20.));
    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    uint8_t seed[32];
    assert(getrandom(seed, 32, 0) == 32);
    assert(secp256k1_context_randomize(ctx, seed));
    std::vector<std::vector<uint8_t>> privKeys;
    std::vector<std::vector<uint8_t>> pubKeys;
    for (int i = 0; i < n; ++i)
    {
        uint8_t key[32];
        while (true)
        {
            auto rc = getrandom(key, 32, 0);
            assert(rc == 32);
            if (secp256k1_ec_seckey_verify(ctx, key))
            {
                break;
            }
        }
        privKeys.emplace_back(key, key + 32);
        secp256k1_pubkey pubKey{};
        int rc = secp256k1_ec_pubkey_create(ctx, &pubKey, key);
        assert(rc);
        uint8_t compKey[33];
        size_t outLen = 33;
        rc = secp256k1_ec_pubkey_serialize(ctx, compKey, &outLen, &pubKey, SECP256K1_EC_COMPRESSED);
        assert(rc);
        pubKeys.emplace_back(compKey, compKey + outLen);
    }
    for (int i = 0; i < n; ++i)
    {
        //        Ptr<Socket> ns3TcpSocket =
        //            Socket::CreateSocket(nodes.Get(0), TcpSocketFactory::GetTypeId());
        //    ns3TcpSocket->TraceConnectWithoutContext("CongestionWindow",
        //    MakeCallback(&CwndChange));

        Ptr<zyza::ZyzaReplica> app = CreateObject<zyza::ZyzaReplica>(
            n,
            i,
            p2psh,
            pubKeys,
            std::span<const uint8_t>{privKeys[i].begin(), privKeys[i].end()});
        //        zyza::ZyzaReplica aaa(n,
        //                                            i,
        //                                            nodes,
        //                                            interfaces,
        //                                            pubKeys,
        //                                            {privKeys[i].begin(), privKeys[i].end()}) ;
        //        app->Setup(ns3TcpSocket, sinkAddress, 1040, 1000, DataRate("1Mbps"));
        p2psh.GetSpokeNode(i)->AddApplication(app);
        app->SetStartTime(Seconds(0));
        app->SetStopTime(Seconds(2000));
    }
    Ipv4GlobalRoutingHelper::PopulateRoutingTables();
    std::clog << "start sim" << std::endl;
    //    devices.Get(1)->TraceConnectWithoutContext("PhyRxDrop", MakeCallback(&RxDrop));
    //    csma.EnablePcapAll("localnet");
    Simulator::Stop(Seconds(2000));
    Simulator::Run();
    Simulator::Destroy();

    return 0;
}
