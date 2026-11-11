//! The side tables `outbound_intent_ledger` keeps (core split slice 1): each row declares one, and the crate's
//! build script places it in `side_table`'s catalogue.

crate::side_table::side_tables! {
    /// A call a restore holds no record of, as its record kept its accounting and state outside
    /// the call's compartment (KS7-5, FIX 12117): the six-entry MessagePack map of its budget
    /// marker, recorded outcome, delivery uncertainty, state and clocks. Such a call is never
    /// admitted again. Key: id16(attempt) + u64be(call seq).
    OUTBOUND_INTENT_ACCOUNTING: VaultMeta b"outbound:intent_accounting:v1:" Raw
        [restore: live] [family: owner OutboundCall] [tier: canonical];
    /// Unique index from one logical dispatch call to its immutable intent id. Key: id16(attempt) +
    /// u64be(call seq).
    OUTBOUND_INTENT_ATTEMPT_INDEX: VaultMeta b"outbound:intent_attempt:v1:" Raw
        [restore: live] [family: owner OutboundCall] [tier: canonical];
    /// Format-version marker gating the attempt index; a non-empty unindexed ledger fails closed.
    /// Key: ().
    OUTBOUND_INTENT_ATTEMPT_FORMAT: VaultMeta b"outbound:intent_attempt_format" Raw
        [restore: live] [family: structure] [tier: canonical];
    /// A send linked to a deleted PERSON its party names, for that person's erase (FIX 11030).
    /// Key: id16(person) + hash32 (intent id).
    OUTBOUND_INTENT_LATE_RECIPIENT: VaultMeta b"outbound:intent_late_recipient:v1:" Named
        [restore: live] [family: unregistered] [tier: canonical];
    /// Durable outbound-send intent ledger row: state machine, endpoint binding, and accounting. Key:
    /// hash32. An actor's erase takes the request of each row it admitted (FIX 9283).
    OUTBOUND_INTENT_LEDGER_RECORD: VaultMeta b"outbound:intent_ledger:v2:" Raw Authored [accepts: crate::outbound_intent_ledger::outbound_intent_ledger_record_accepts_masked]
        [restore: live] [family: owner OutboundCall] [tier: canonical]
        => crate::outbound_intent_ledger::erase_outbound_intent_actor_in_txn;
    /// A send whose counterparty resolved to no PERSON at admission, by the BLAKE3 digest of its
    /// exact party key (FIX 11030). Key: hash32 (party digest) + hash32 (intent id).
    OUTBOUND_INTENT_PARTY: VaultMeta b"outbound:intent_party:v1:" Named
        [restore: live] [family: unregistered] [tier: canonical];
    /// That send's party digest, by its intent id (FIX 11030). Key: hash32 (intent id).
    OUTBOUND_INTENT_PARTY_OF: VaultMeta b"outbound:intent_party_of:v1:" Named
        [restore: live] [family: unregistered] [tier: canonical];
    /// What one ledger row's send came to beside its state, written with the ledger change it
    /// records: its remote task handle (FIX 7960), its provider wait (FIX 8818) and its reserved
    /// budget (FIX 7964), `rmp_serde::to_vec_named`. Key: hash32 (intent id).
    OUTBOUND_INTENT_SETTLEMENT: VaultMeta b"outbound:intent_settlement:v1:" Named
        [restore: live] [family: unclassified] [tier: canonical];
    /// A call a restore holds no record of, as its per-tool bound counts it (FIX 6260): the
    /// digest of its server and tool, then its admission times. Key: id16(attempt) + u64be(call
    /// seq).
    OUTBOUND_INTENT_UNAVAILABLE: VaultMeta b"outbound:intent_unavailable:v1:" Raw
        [restore: live] [family: owner OutboundCall] [tier: canonical];
    /// A Deferred send's remote task form question, parked for the owner (FIX 16029): its round's
    /// generation, phase, question digest, owner Ask, field names, connector and tool, and the
    /// request and answer sealed under the intent's own ConnectorResume subject; no plaintext.
    /// The ledger's erase of the call, its actor or its recipient forgets it. Key: hash32 (intent
    /// id).
    OUTBOUND_REMOTE_TASK_INPUT: VaultMeta b"outbound:remote_task_input:v1:" Named
        // Restore class: A parked task question stands with the live send and its live custody key
        // (FIX 16029): live state replaces the image's; absent stays absent. Its owner Ask restores
        // as content (DECISION_ASK), so the poller's pass (`forget_ended_remote_task_inputs`)
        // reconciles the two: an Ask of a question no row holds is withdrawn, and a waiting row's
        // missing Ask is queued again, each Ask checked by its typed identity, never its number.
        // Payload family: A remote task's parked question is live runtime state, sealed under this
        // vault's own ConnectorResume key, which no image carries (FIX 16029).
        [restore: live] [family: not_imaged] [tier: canonical];
    /// A Deferred send's remote task poll (FIX 11023): its next poll time, poll count and last
    /// status word; the session and credential choice stay in the settlement's handle. Key:
    /// hash32 (intent id).
    OUTBOUND_REMOTE_TASK_POLL: VaultMeta b"outbound:remote_task_poll:v1:" Named
        [restore: live] [family: unregistered] [tier: canonical];
    /// An MCP session a remote task's polls kept open, owed its end once its handle went before
    /// the session ended (an erase; FIX 16028): where it is and the credential that opens it.
    /// Key: hash32 (intent id).
    OUTBOUND_REMOTE_TASK_SESSION_END: VaultMeta b"outbound:remote_task_session_end:v1:" Named
        [restore: live] [family: unregistered] [tier: canonical];
}
