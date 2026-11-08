//! The side tables `anchored_annotation` keeps (core split slice 1): each row declares one, and the crate's
//! build script places it in `side_table`'s catalogue.

crate::side_table::side_tables! {
    /// The anchor a thread held before one re-anchor sweep moved it onto a version, so a restore
    /// of that earlier version reattaches it by exact stored identity. Key: id16 (artifact) +
    /// id16 (thread) + u64be (the version it moved to).
    ANNOTATION_PRIOR_ANCHOR: VaultMeta b"anchored_annotation:prior:v1:" Named
        [restore: content] [family: unclassified] [tier: canonical];
    /// A detached comment's snapshot of the text it was anchored on, for the Unattached list and
    /// the exact-words reattach offer. Key: id16 (artifact) + id16 (thread).
    ANNOTATION_UNATTACHED: VaultMeta b"anchored_annotation:unattached:v1:" Named
        [restore: content] [family: unclassified] [tier: canonical];
}
