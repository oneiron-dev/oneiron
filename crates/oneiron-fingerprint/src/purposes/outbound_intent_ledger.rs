//! Purposes of the outbound intent ledger (`crates/oneiron/src/outbound_intent_ledger`).

purposes! {}

legacy_purposes! {
    /// The outbound intent id (`derive_intent_id`). Plain BLAKE3, with no tag written, of
    /// the sorted-key JSON of `{attempt_id, call_seq, payload_hash, server, tool}`
    /// (`crate::llm::canonical_json_bytes`; the byte arrays as JSON number lists). Stored as
    /// `IntentLedgerRecord.id`, the ledger row's key and its idempotency key.
    INTENT_ID = (Blake3, NotHashed, "oneiron.outbound_intent_ledger.intent_id.v1");
}
