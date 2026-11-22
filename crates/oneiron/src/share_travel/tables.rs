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
    /// A row this vault released to a grant's peer in another vault
    /// (CROSS-VAULT-DELETE-SELECTOR-ANSWER-RELEASE), written before the bytes leave; never a claim
    /// of delivery. It outlives the row's erase: the owner's delete travels after the row is gone.
    /// Key: id16(grant) + id16(row). Value: u64 (first release, recorded-clock seconds).
    SHARE_PEER_RELEASE: VaultMeta b"share:peer:release:v1:" Named
        // Restore class: the peer still holds what it was sent, so the record stays as the live
        // vault holds it, as the export travel receipts do.
        [restore: live] [family: unclassified] [tier: canonical];
}
