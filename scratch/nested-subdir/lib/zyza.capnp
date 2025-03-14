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

struct AckList {
    proposalHash @0 :Data;
    acknowledgements1 @1 :List(Signature);
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

struct ResponseProofBody {
    id @0 :UInt64;
    implHash @1 :Data;
    proposalHash @2 :Data;
}

struct Response {
    impl @0 :Data;
    proof @1 :SignedMessage; #SignedMessage<ResponseProofBody>
}

struct ClientResponse {
    id @0 :UInt64;
    union {
        completed @1 :Completed;
        canceled @2 :Canceled;
    }
    struct Completed {
        proofBody @0 :Data; # Data<ResponseProofBody>
        proof @1 :List(Signature);
    }
    struct Canceled {
        backupLeader @0 :UInt16;
        proof @1 :List(Signature);
    }
}

struct RequestCancelBody {
    id @0 :UInt64;
    backupLeader @1 :UInt16;
}

struct ProposalBody {
    prevProposalHash @0 :Data;
    requests @1 :List(Request);
    ord @2 :UInt32;
}

struct Proposal {
    signedProposal @0 :Data; # Data<SignedMessage<ProposalBody>>
    acknowledgements2 @1 :List(List(Signature));
}

struct Acknowledgement {
    hash @0 :Data;
    sign @1 :Signature;
}

struct FallbackAlertBody {
    lastAckedProposalHash @0 :Data;
    unackedSignedProposals @1 :List(Data); # List(Data<SignedMessage<ProposalBody>>)
    union {
        lastAckList @2 :AckList;
        noAckList @3 :Void;
    }
}

struct RecoveryStateBody {
    alerts @0 :List(SignedMessage); # List(SignedMessage<FallbackAlertBody>)
}

struct ClientResponsesBody {
    recoveryStateBodyHash @0 :Data;
    responses @1 :List(ClientResponse);
}

struct RecoveryBody {
    clientResponses @0 :List(SignedMessage); # List(SignedMessage<ClientResponsesBody>)
}

struct ResendChainRequest {
    idx @0 :UInt16;
    lastAckedProposalHash @1 :Data;
}

struct ResendChainResponse {
    proposals @0 :List(Data); # List(Data<SignedMessage<ProposalBody>>)
    acknowledgements1 @1 :List(AckList);
    acknowledgements2 @2 :List(List(Signature));
}
