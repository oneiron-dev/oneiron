//! The side tables `scope_summary` keeps (core split slice 1): each row declares one, and the crate's
//! build script places it in `side_table`'s catalogue.

crate::side_table::side_tables! {
    /// One row of an Arc's durable work generation (FIX 7509 PR3): its manifest, a part's progress or
    /// its assembly, as refs, pins, ranges and step refs only. Key: string (work id hex + typed suffix).
    SCOPE_SUMMARY_ARC_WORK: VaultMeta b"scope_summary:arc_work:v1:" Named
        [restore: content] [family: unclassified] [tier: canonical];
    /// Active scope-summary projection and its last observed input hash. Key: hash32.
    SCOPE_SUMMARY_PROJECTION: VaultMeta b"scope_summary:projection:v1:" Named
        [restore: content] [family: unclassified] [tier: canonical];
    /// Owner-approved summary-purpose descriptor. Key: string (descriptor id).
    SCOPE_SUMMARY_PURPOSE: VaultMeta b"scope_summary:purpose:v1:" Named
        [restore: live] [family: unclassified] [tier: canonical];
    /// Atomic summary/landing result of one queued declaration. Key: AttemptId.
    SCOPE_SUMMARY_RESULT: VaultMeta b"scope_summary:result:v1:" Named
        [restore: content] [family: unclassified] [tier: canonical];
}
