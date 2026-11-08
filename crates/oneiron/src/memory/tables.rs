//! The side tables `memory` keeps (core split slice 1): each row declares one, and the crate's
//! build script places it in `side_table`'s catalogue.

crate::side_table::side_tables! {
    /// In-transaction booking publication write marker. Key: id16.
    BOOKING_PUBLICATION_WRITE_STAGE: VaultMeta b"booking.public_write.in_txn/" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Marker for a ruled conflict packet. Key: bytes32.
    CLAIM_CONFLICT_RESOLUTION: VaultMeta b"consent_bundle.claim_conflict.resolved.v1:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Content-addressed claim-conflict review packet. Key: bytes32.
    CLAIM_CONFLICT_PACKET: VaultMeta b"consent_bundle.claim_conflict.v1:" LegacyJson
        [restore: content] [family: unclassified] [tier: canonical];
    /// OF-490: one read of an agent's diary: reader, stated reason, entries and Grants (the agent
    /// sees it). Key: id16 (agent) + id16 (read).
    DIARY_READ_LOG: VaultMeta b"diary:read_log:v1:" Named
        [restore: live] [family: unclassified] [tier: canonical];
    /// OF-490: a reader's reason waiting on, or answered by, the agent's Y/N review. Key: id16
    /// (agent) + id16 (request).
    DIARY_READ_REQUEST: VaultMeta b"diary:read_request:v1:" Named
        [restore: live] [family: unclassified] [tier: canonical];
    /// OF-490: an agent reviews each read of its diary before it is read (on for Eiri; absent
    /// means off). Value: one byte, 1 on, 0 off. Key: id16 (agent).
    DIARY_READ_REVIEW: VaultMeta b"diary:read_review:v1:" Raw
        [restore: live] [family: unclassified] [tier: canonical];
    /// The export audit (FIX 6427): one row per Owner copy that left the vault, the whole vault
    /// or an off-record room's talk. It holds the export id, scope, exporter, time, format and
    /// actor, and the copy's length and digest where its door read the copy back; never the
    /// exported bytes. Key: u64be(sequence).
    EXPORT_RECEIPT: VaultMeta b"export:receipt:v1:" Named
        [restore: live] [family: unclassified] [tier: canonical];
    /// FIX 9970: a TURN whose landing could not record its program wake, and why, written in
    /// that landing's commit and cleared when a later landing of the turn evaluates its wake.
    /// Key: id16(turn).
    MEMORY_TURN_WAKE_UNPERSISTED: VaultMeta b"memory:turn_wake_unpersisted:v1:" Named Engine
        // Restore class: FIX 9970: a turn's unpersisted-wake label stands with the turn as the
        // image holds it, as the wakes its landing did record do.
        [restore: content] [family: unclassified] [tier: canonical];
    /// The reply assertions a MESSAGE born whole (not streamed) kept from its witness write
    /// (FIX 10260): its turn, conversation and writer, and the ids and types its turn asserted.
    /// Key: id16(message).
    MESSAGE_REPLY_ASSERTIONS: VaultMeta b"message_reply_assertions:v1:" Named Engine
        // Restore class: Content-owned audit, never authority (FIX 10260).
        // Payload family: The reply assertions a MESSAGE born whole kept (FIX 10260), carried whole
        // (FIX 10631).
        [restore: content] [family: dispatch Response] [tier: canonical];
    /// The stream generations an erase dropped, so a resident stream of one reads as gone once
    /// the erase commits (FIX 9973). Key: hex32(message id) ":" hex32(generation).
    MESSAGE_STREAM_ERASED: VaultMeta b"message_stream_erased:v1:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Vault default message-streaming policy. Key: ().
    MESSAGE_STREAM_POLICY: VaultMeta b"message_stream_policy:v1" Named
        [restore: live] [family: unclassified] [tier: canonical];
    /// Latest terminal stream receipt of a message. Key: id16.
    MESSAGE_STREAM_RECEIPT: VaultMeta b"message_stream_receipt:v1:" Named
        [restore: content] [family: unclassified] [tier: canonical];
    /// One explicitly reviewed run's settlement and compensating-operation handles. Key: job id.
    RUN_REVIEW_SETTLEMENT: VaultMeta b"run_review:settlement:v1:" Named
        [restore: content] [family: unclassified] [tier: canonical]
        => crate::memory::run_review::erase_run_review_actor_in_txn;
    /// Per-generation stream receipt keyed by its receipt ref. Key: hex32 ":" hex32.
    MESSAGE_STREAM_RECEIPT_BY_REF: VaultMeta b"stream:v1:" Named
        [restore: content] [family: unclassified] [tier: canonical];
}
