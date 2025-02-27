@0x85150b117366d14b;

using Cxx = import "/capnp/c++.capnp";
$Cxx.namespace("zyza::proto");

struct Signature {
    idx @0 :UInt16;
    sign @1 :Data;
}

struct SignedMessage {
    body @0 :Data;
    sign @1 :Signature;
}

struct Request {
    impl @0 :Data;
    id @1 :UInt64;
    respAddr @2 :Text;
    respPort @3 :UInt16;
}

struct Redirect {
    redirect @0 :UInt16;
}

struct ResponseBody {
    impl @0 :Data;
    id @1 :UInt64;
    proposalHash @2 :Data;
}

struct ClientResponse {
    id @0 :UInt64;
    proposalHash @1 :Data;
    union {
        completed @2 :List(Signature);
        canceled @3 :Bool;
    }
}

struct RequestCancelBody {
    id @0 :UInt64;
    proposalHash @1 :Data;
    alertListHash @2 :Data;
}

struct ProposalBody {
    prevProposalHash @0 :Data;
    requests @1 :List(Request);
    ord @2 :UInt32;
}

struct Proposal {
    signedProposal @0 :Data;
    acknowledgements @1 :List(List(Signature));
}

struct Acknowledgement {
    proposalHash @0 :Data;
    sign @1 :Signature;
}

struct FallbackAlertBody {
    lastAckedProposalHash @0 :Data;
    unackedSignedProposals @1 :List(Data);
}

struct AlertList {
    alerts @0 :List(SignedMessage);
}

struct ProposalCancelResponseBody {
    proposalHash @0 :Data;
    clientResponses @1 :List(ClientResponse);
}

struct RecoveryBody {
    alerts @0 :AlertList;
    proposalCancelResponses @1 :List(List(SignedMessage));
}

struct RecoveryAck {
    recoveryHash @0 :Data;
    sign @1 :Signature;
}

struct ResendChainRequest {
    idx @0 :UInt16;
    lastAckedProposalHash @1 :Data;
}

struct ResendChainResponse {
    proposals @0 :List(Data);
    acknowledgements @1 :List(List(Signature));
}
