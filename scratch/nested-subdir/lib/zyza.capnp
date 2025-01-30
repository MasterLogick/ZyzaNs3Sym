@0x85150b117366d14b;

using Cxx = import "/capnp/c++.capnp";
$Cxx.namespace("zyza::proto");

struct Signature {
    idx @0 :UInt16;
    sign @1 :Data;
}

struct Request {
    impl @0 :Data;
    id @1 :UInt64;
    dropHash @2 :Data;
    respAddr @3 :Text;
    respPort @4 :UInt16;
}

struct ResponseBody {
    impl @0 :Data;
    id @1 :UInt64;
    proposalHash @2 :Data;
}

struct Response {
    body @0 :Data;
    sign @1 :Signature;
}

struct ProposalBody {
    prevProposalHash @0 :Data;
    acknowledgements @1 :List(Signature);
    requests @2 :List(Request);
    ord @3 :UInt32;
}

struct Proposal {
    body @0 :Data;
    sign @1 :Signature;
}

struct Acknowledgement {
    proposalHash @0 :Data;
    sign @1 :Signature;
}

struct QuorumCertificate {
    response @0 :ResponseBody;
    signs @1 :List(Signature);
}

struct Redirect {
    redirect @0 :UInt16;
}

struct FallbackAlert {
    unackedProposal @0 :Data;
    sign @1 :Signature;
}

struct QuorumDropRequest {
    proof @0 :List(FallbackAlert);
    reqId @1 :UInt64;
}

struct QuorumDropResponse {
    reqId @0 :UInt64;
    dropSecret @1 :Data;
}

struct Recovery {
    proof @0 :List(FallbackAlert);
    union {
        quorumCertificate @1 :QuorumCertificate;
        clientResponses @2 :List(ClientResponse);
    }
    struct ClientResponse {
        reqId @0 :UInt64;
        dropSecret @1 :Data;
    }
}

struct NetworkStatusRequest {
    idx @0 :UInt16;
}

struct NetworkStatusResponse {
    currentLeader @0 :UInt16;
}

struct ResendChainRequest {
    idx @0 :UInt16;
    lastAckedProposal @1 :Data;
}

struct ResendChainResponse {
    chainPart @0 :List(Proposal);
}