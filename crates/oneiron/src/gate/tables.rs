//! The side tables `gate` keeps (core split slice 1): each row declares one, and the crate's
//! build script places it in `side_table`'s catalogue.

crate::side_table::side_tables! {
    /// Marks a policy-manifest contribution as quarantined by an explicit owner action. Key: hex32.
    GATE_MANIFEST_QUARANTINED: SyncState b"manifest:quarantined:" Raw
        [restore: live] [family: unclassified] [tier: canonical];
    /// Maps a legacy policy-manifest id forward to its re-authored replacement id. Key: hex32.
    GATE_MANIFEST_REKEY: SyncState b"manifest:rekey:" Raw
        [restore: live] [family: unclassified] [tier: canonical];
    /// Body hash (blake3, 32 bytes) proving an authenticated vault owner authored a retention
    /// override manifest; any generic write of the manifest clears it. Key: hex32.
    GATE_MANIFEST_RETENTION_HOLDER: SyncState b"manifest:retention-holder:" Raw
        [restore: live] [family: unclassified] [tier: canonical];
    /// Per-actor foreign-introduction ceiling and widen state for an owner-bound agent introduction.
    /// Key: id16.
    GATE_FOREIGN_AGENT_INTRODUCTION: VaultMeta b"gate.foreign-agent.v1:" Named
        [restore: live] [family: unclassified] [tier: canonical];
    /// Cached configuration window (seconds) for the receipt-derived auto-checker signal; no engine
    /// write path found in this repo, likely operator-provisioned. Key: ().
    GATE_AUTO_SIGNALS_WINDOW: VaultMeta b"gate:auto_signals:window:v1" LegacyJson
        [restore: live] [family: unclassified] [tier: canonical];
    /// Number and first threshold-crossing for one actor. Key: id16.
    PROPOSAL_ACTOR_COUNT: VaultMeta b"proposal:actor_count:v1:" Named
        [restore: content] [family: unclassified] [tier: canonical]
        => crate::store::gate_hooks::erase_count_actor_in_txn;
    /// Immutable receipt for one actor and monotonically increasing submission count. Key: id16 ":" u64be.
    PROPOSAL_RECEIPT_HISTORY: VaultMeta b"proposal:receipt:v1:" Named
        [restore: content] [family: unclassified] [tier: canonical]
        => crate::store::gate_hooks::erase_history_actor_in_txn;
    /// Latest receipt keyed by actor id16 ":" proposal identity string.
    PROPOSAL_SUBMISSION: VaultMeta b"proposal:submission:v1:" Named
        [restore: content] [family: unclassified] [tier: canonical]
        => crate::store::gate_hooks::erase_submission_actor_in_txn;
}
