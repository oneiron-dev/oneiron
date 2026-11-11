//! The side tables `linkedin_connector` keeps (core split slice 1): each row declares one, and the crate's
//! build script places it in `side_table`'s catalogue.

crate::side_table::side_tables! {
    /// Durable provenance row (source/tier/thread/message/surface-event) for one ingested LinkedIn
    /// message. Key: hex16 (same hash as the seen marker).
    LINKEDIN_INBOX_SYNC_PROVENANCE: SyncState b"linkedin:inbox_sync:provenance:v1:" LegacyJson
        [restore: content] [family: unclassified] [tier: canonical];
    /// Claim-then-finalize dedupe marker for one polled LinkedIn inbox message, or a seat's poll
    /// cursor. Message key: hex16 (truncated blake3 of receiving address/session/thread/message).
    /// Cursor key: `cursor:` + hex16 (truncated blake3 of receiving address/session).
    LINKEDIN_INBOX_SYNC_SEEN: SyncState b"linkedin:inbox_sync:seen:v1:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
}
