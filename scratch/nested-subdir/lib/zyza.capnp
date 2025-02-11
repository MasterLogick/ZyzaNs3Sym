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

struct ProposalBody {
    prevProposalHash @0 :Data;
    acknowledgements @1 :List(List(Signature));
    requests @2 :List(Request);
    ord @3 :UInt32;
}

struct Acknowledgement {
    hash @0 :Data;
    sign @1 :Signature;
}

struct FallbackAlertBody {
    unackedProposals @0 :List(Data);
}

struct ProposalStatusRequest {
    proposalHash @0 :Data;
    idx @1 :UInt16;
}

struct ProposalStatusResponseBody {
    proposalHash @0 :Data;
    union {
        acks @1 :List(Signature);
        notEnoughAcks @2 :UInt8;
    }
}

struct Recovery {
    alerts @0 :List(SignedMessage);
    union {
        enoughAcks @1 :EnoughAcksRecovery;
        notEnoughAcks @2 :NotEnoughAcksRecovery;
    }
    struct EnoughAcksRecovery {
        ackedPart @0 :List(List(SignedMessage));
        unackedPart @1 :List(List(SignedMessage));
    }
    struct NotEnoughAcksRecovery {
        psrs @0 :List(List(SignedMessage));
    }
}

struct RecoveryAck {
    recoveryHash @0 :Data;
    sign @1 :Signature;
}

struct ResendChainRequest {
    idx @0 :UInt16;
    lastAckedProposal @1 :Data;
}

struct ResendChainResponse {
    chainPart @0 :List(SignedMessage);
}