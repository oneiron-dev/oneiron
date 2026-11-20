//! The side tables `idle_fold` keeps (L2-37): one row per parked canonical wait, the return
//! cells the Coach's weekly pass derives from those rows, and each parked wait's due idle call,
//! the call it got and the folds it landed. The crate's build script places them in
//! `side_table`'s catalogue.

crate::side_table::side_tables! {
    /// One parked canonical code-run wait (L2-37): its session kind and wait class, when it
    /// parked and when its reply came back, both on the wall clock in milliseconds, or that it
    /// never came back. Observations, so no pass can derive them again; ids and times only, no
    /// body. Key: id16(run) + id16(wait) + generation u64 BE, the wait's own row key.
    IDLE_FOLD_WAITS: VaultMeta b"idle_fold:waits:v1:" Named
        [restore: content] [family: unclassified] [tier: canonical];
    /// The return gaps of the trailing eight weeks' waits by session kind, wait class, four-hour
    /// band and weekend, rebuilt weekly from IDLE_FOLD_WAITS: the sorted gaps in seconds and the
    /// count that never came back. Key: [session kind, wait class, band, weekend], one byte each.
    IDLE_FOLD_RETURN_CELLS: VaultMeta b"idle_fold:return_cells:v1:" Named
        [restore: not_imaged] [family: not_imaged] [tier: derived];
    /// When the weekly pass last rebuilt IDLE_FOLD_RETURN_CELLS, in unix seconds. Key: ().
    IDLE_FOLD_RETURN_CELLS_BUILT: VaultMeta b"idle_fold:return_cells_built:v1" Raw
        [restore: not_imaged] [family: not_imaged] [tier: derived];
    /// A parked wait's due idle call (L2-37 PR-2): the prompt prefix its run's last turn answer
    /// left cached (when its send went out, its lifetime, its tokens, the model that answered),
    /// the parked attempt, the run's agent and the due time in unix milliseconds. Written right
    /// after the park, gone once the call is made or the wait closes. Ids, times and counts
    /// only, no body. This node's own working state: the provider holds the prefix for this
    /// runtime's calls only, so no image carries the row, and a restore never plants a call for
    /// a prefix long gone. Key: id16(run) + id16(wait) + generation u64 BE.
    IDLE_FOLD_DUE: VaultMeta b"idle_fold:due:v1:" Named
        [restore: not_imaged] [family: not_imaged] [tier: runtime];
    /// The idle call each parked wait got (L2-37 PR-2): Fold, with the folds it landed and the
    /// prompt tokens their bodies held, or Expire, and when, for the replay check. Observations,
    /// no body. Key: id16(run) + id16(wait) + generation u64 BE.
    IDLE_FOLD_CALLS: VaultMeta b"idle_fold:calls:v1:" Named
        [restore: content] [family: unclassified] [tier: canonical];
    /// The folds idle calls landed while their run was parked (L2-37 PR-2), which the run's next
    /// entry takes as its first brief boundary and deletes. Fold numbers only. Key: id16(run).
    IDLE_FOLD_BOUNDARIES: VaultMeta b"idle_fold:fold_boundaries:v1:" Named
        [restore: content] [family: unclassified] [tier: canonical];
}
