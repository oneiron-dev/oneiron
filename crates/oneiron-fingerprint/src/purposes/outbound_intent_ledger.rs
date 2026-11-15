//! Purposes of the outbound intent ledger (`crates/oneiron/src/outbound_intent_ledger`).

purposes! {
    /// An outbound intent's approval ask (`outbound_chokepoint::ordinary_slate`). Parts: the
    /// intent record, the candidate's digest.
    INTENT_APPROVAL_ASK = "oneiron:outbound-intent-approval-ask:v1";

    /// A remote task input Ask's question id and correlation
    /// (`outbound_intent_ledger::remote_task_input::owner_ask`). Parts: intent, question
    /// digest, the round's generation.
    REMOTE_TASK_INPUT_ASK = "oneiron:outbound-remote-task-input-ask:v1";
}

legacy_purposes! {
    /// The outbound intent id (`derive_intent_id`). Plain BLAKE3, with no tag written, of
    /// the sorted-key JSON of `{attempt_id, call_seq, payload_hash, server, tool}`
    /// (`crate::llm::canonical_json_bytes`; the byte arrays as JSON number lists). Stored as
    /// `IntentLedgerRecord.id`, the ledger row's key and its idempotency key.
    INTENT_ID = (Blake3, NotHashed, "oneiron.outbound_intent_ledger.intent_id.v1");
}
