//! Purposes of connectors (`crates/oneiron/src/connector_key`, `ingest::connector_*`,
//! `outbound_consent`, `outbound::reply_job`, `linear_sync`).

purposes! {
    /// A credential binding's ref (`connector_key::credential_binding`). Parts: catalog key,
    /// credential slot.
    CREDENTIAL_BINDING = "oneiron:connector-credential-binding:v1";

    /// A scope signal's id (`connector_key::slate_scope_signal`). Parts: its call's principal,
    /// attempt and sequence (u64 little-endian).
    SCOPE_SIGNAL = "oneiron:connector-scope-signal:v1";

    /// A connector conversation (`ingest::connector_conversation`). Parts: channel,
    /// receiving identity, provider thread (empty when none), audience (the reply target).
    CONVERSATION = "oneiron.ingest.connector.conversation.v1";

    /// A connector conversation's TURN (`ingest::connector_conversation`). Parts:
    /// conversation, then the side.
    TURN = "oneiron.ingest.connector.turn.v1";

    /// A connector conversation's MESSAGE (`ingest::connector_conversation`). Parts:
    /// conversation, then the side.
    MESSAGE = "oneiron.ingest.connector.message.v1";

    /// A witness-read grant (`ingest::connector_witness_grant`). Parts: the agent, then the
    /// conversation.
    WITNESS_READ_GRANT = "oneiron.ingest.connector.witness_read_grant.v1";

    /// The call ref a host's own identity fixes, so the same logical call finds its held row
    /// again (`outbound_consent::connector_call`). Parts: principal, attempt, call sequence
    /// (u64 little-endian).
    CALL_REF = "oneiron:connector-call-ref:v1";

    /// An elicitation ask's correlation (`outbound_consent::connector_elicitation_asks`).
    /// Parts: handle, generation (little-endian), digest.
    ELICITATION_ASK = "oneiron:connector-elicitation-ask:v1";

    /// A linked part's question id (`outbound_consent::connector_elicitation_asks`). Parts:
    /// handle, generation (little-endian), digest, time (u64 little-endian).
    ELICITATION_ASK_PART = "oneiron:connector-elicitation-ask-part:v1";

    /// An answer check's correlation (`outbound_consent::connector_elicitation_asks`). Parts:
    /// handle, generation (little-endian), digest.
    ELICITATION_ANSWER_CHECK = "oneiron:connector-elicitation-answer-check:v1";

    /// A reply job result's artifact, one per job attempt (`outbound::reply_job`). Parts:
    /// attempt.
    REPLY_JOB_RESULT = "oneiron:connector-reply-job-result:v1";

    /// A Linear mirror body occurrence (`linear_sync::custody`). Parts: the operation id,
    /// then the body's role.
    LINEAR_MIRROR_BODY = "oneiron:linear-mirror-body:v1";
}

legacy_purposes! {}
