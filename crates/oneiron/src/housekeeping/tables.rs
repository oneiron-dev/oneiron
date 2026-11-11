//! The side tables `housekeeping` keeps (core split slice 1): each row declares one, and the crate's
//! build script places it in `side_table`'s catalogue.

crate::side_table::side_tables! {
    /// One engine housekeeping sweep's schedule: when it is next due, when its last run finished,
    /// and whether a run is in flight. Key: string (the sweep's code).
    HOUSEKEEPING_SCHEDULE: VaultMeta b"housekeeping:v1:" Named
        [restore: live] [family: unclassified] [tier: canonical];
}
