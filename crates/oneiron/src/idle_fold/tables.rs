//! The side tables `idle_fold` keeps (L2-37): one row per parked canonical wait, and the return
//! cells the Coach's weekly pass derives from those rows. The crate's build script places them in
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
}
