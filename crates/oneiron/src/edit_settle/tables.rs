//! The side tables `edit_settle` keeps (core split slice 1): each row declares one, and the crate's
//! build script places it in `side_table`'s catalogue.

crate::side_table::side_tables! {
    /// The delta receipt id a Selected Keep answered (FIX 11706), so its undo
    /// anchors the routing outcome. Key: id16 + hash32 (blake3 of the proposal ref).
    EDIT_SETTLE_KEEP_LINK: VaultMeta b"edit_settle:keep_link:v1:" Named
        [restore: content] [family: unclassified] [tier: canonical];
    /// An organ call held until one of the owner's nodes can run it (OF-575 MESH): the call's
    /// bytes, why it waits, and its tries. Key: id16 + hash32 (blake3 of the run ref).
    EDIT_SETTLE_ORGAN_WAIT: VaultMeta b"edit_settle:organ_wait:v1:" Named
        [restore: live] [family: unclassified] [tier: canonical];
    /// A proposal retained beside its artifact until Keep or Discard: an edit proposal or a native
    /// organ output. Key: id16 + hash32 (blake3 of the proposal ref).
    EDIT_SETTLE_PENDING_PROPOSAL: VaultMeta b"edit_settle:pending:v1:" Named
        [restore: content] [family: unclassified] [tier: canonical];
    /// Stranded edit proposal. Key: id16 + hash32.
    EDIT_SETTLE_STRANDED_PROPOSAL: VaultMeta b"edit_settle:stranded:v1:" Named
        [restore: content] [family: unclassified] [tier: canonical];
    /// The once-only undo of one kept proposal: the version it restored. Key: id16 + hash32.
    EDIT_SETTLE_UNDO: VaultMeta b"edit_settle:undo:v1:" Named
        [restore: content] [family: unclassified] [tier: canonical];
    /// The answers of one held answer proposal whose units changed under it (ARCH-0075 §4): each
    /// with the revision it was judged against, and its proposer's wake. Key: id16 + hash32.
    EDIT_SETTLE_UNIT_WITHDRAWAL: VaultMeta b"edit_settle:withdrawal:v1:" Named
        [restore: content] [family: unclassified] [tier: canonical];
}
