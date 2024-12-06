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
    respAddr @2 :Text;
    respPort @3 :UInt16;
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
    prevGroupHash @0 :Data;
    acknowledgements @1 :List(Signature);
    requests @2 :List(Request);
}

struct Proposal {
    body @0 :Data;
    sign @1 :Signature;
}

struct Acknowledgement {
    groupHash @0 :Data;
    groupSign @1 :Signature;
}

struct QuorumCertificate {
    response @0 :ResponseBody;
    signs @1 :List(Signature);
}

struct Redirect {
    redirect @0 :UInt16;
}
