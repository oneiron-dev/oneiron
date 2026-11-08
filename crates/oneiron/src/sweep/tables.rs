//! The side tables `sweep` keeps (core split slice 1): each row declares one, and the crate's
//! build script places it in `side_table`'s catalogue.

crate::side_table::side_tables! {
    /// What the compaction scrub reads in an owning adapter's carrier whose body lives in a
    /// file (FIX 22091): holder, birth child, receipt-archive flag, owned-id flag and copied-id
    /// fingerprints. No payload. Key: id16 + blake3 (32 bytes) of the body.
    ASSET_CARRIER_SCRUB_FACTS: VaultMeta b"asset:carrier_scrub_facts:v1:" Named
        [restore: content] [family: structure] [tier: canonical];
}
