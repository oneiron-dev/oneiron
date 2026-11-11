//! The side tables `session_lifecycle` keeps (core split slice 1): each row declares one, and the crate's
//! build script places it in `side_table`'s catalogue.

crate::side_table::side_tables! {
    /// Open SESSION per actor and machine. Key: actor id16 + machine id16.
    SESSION_LIFECYCLE_OPEN: VaultMeta b"session_lifecycle:v0:open:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Per-session lifecycle clock record (started_at, last_activity, ended_at, end_reason) and its
    /// bound speakers (FIX 2015), keyed by SESSION entity id. Key: id16.
    SESSION_LIFECYCLE_RECORD: VaultMeta b"session_lifecycle:v0:record:" Named
        [restore: content] [family: unclassified] [tier: canonical]
        => crate::session_lifecycle::erase_session_speaker_actor_in_txn;
}
