//! The side tables `share_travel` keeps (core split slice 1): each row declares one, and the crate's
//! build script places it in `side_table`'s catalogue.

crate::side_table::side_tables! {
    /// The born-with text one brief share lets travel (OF-491), fixed in the transaction that
    /// admits the share. Key: id16(share).
    SHARE_BRIEF_TRAVEL: VaultMeta b"share:brief:travel:v1:" Named
        [restore: refuse "share admissions"] [family: unclassified] [tier: canonical];
    /// One artifact export's travel receipt (OF-491): the copy, its digest, who sent it and the
    /// born-with fields that left with it; never the exported bytes. Key: u64be(sequence).
    SHARE_EXPORT_TRAVEL: VaultMeta b"share:export:travel:v1:" Named
        [restore: live] [family: unclassified] [tier: canonical];
}
