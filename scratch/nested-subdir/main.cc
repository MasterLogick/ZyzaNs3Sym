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
#include "ZyzaInfiniteClient.h"
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
    int n = 50;
    int c = 20;

    PointToPointHelper pointToPoint;
    pointToPoint.SetDeviceAttribute("DataRate", StringValue("100Mbps"));
    pointToPoint.SetChannelAttribute("Delay", TimeValue(MilliSeconds(100)));
    PointToPointStarHelper p2psh(n + c, pointToPoint);
    std::clog << "created net devices" << std::endl;
    InternetStackHelper stack;
    p2psh.InstallStack(stack);
    Ipv4AddressHelper addressHelper;
    addressHelper.SetBase("1.0.0.0", "255.255.255.252");
    p2psh.AssignIpv4Addresses(addressHelper);
    std::clog << "assigned net addresses" << std::endl;
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
        Ptr<zyza::ZyzaReplica> app = CreateObject<zyza::ZyzaReplica>(
            n,
            i,
            p2psh,
            pubKeys,
            std::span<const uint8_t>{privKeys[i].begin(), privKeys[i].end()},
            std::chrono::milliseconds(500));
        p2psh.GetSpokeNode(i)->AddApplication(app);
        app->SetStartTime(Seconds(0));
        app->SetStopTime(Seconds(2000));
    }
    for (int i = 0; i < c; ++i)
    {
        Ptr<ZyzaInfiniteClient> app =
            CreateObject<ZyzaInfiniteClient>(i, n, pubKeys, p2psh, std::chrono::milliseconds(900));
        p2psh.GetSpokeNode(n + i)->AddApplication(app);
        app->SetStartTime(Seconds(0));
        app->SetStopTime(Seconds(2000));
    }
    pointToPoint.EnablePcap("g", NodeContainer(p2psh.GetSpokeNode(0)));
    pointToPoint.EnablePcap("g", NodeContainer(p2psh.GetSpokeNode(1)));
    pointToPoint.EnablePcap("g", NodeContainer(p2psh.GetHub()));
    Ipv4GlobalRoutingHelper::PopulateRoutingTables();
    std::clog << "start sim" << std::endl;
    Simulator::Stop(Seconds(2000));
    Simulator::Run();
    Simulator::Destroy();

    return 0;
}
