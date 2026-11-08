//! The side tables `scan_check` keeps (core split slice 1): each row declares one, and the crate's
//! build script places it in `side_table`'s catalogue.

crate::side_table::side_tables! {
    /// The OF-520 check one engine scan raised for one scope, once (`crate::scan_check`; the
    /// origin's scans came first). Key: u8 (scan) + the scope's bytes (a repository's id16, ...),
    /// or the u8 alone for a vault-wide scan.
    ORIGIN_SCAN_CHECK: VaultMeta b"origin:scan_check:v1:" Named
        [restore: live] [family: unclassified] [tier: canonical];
}
