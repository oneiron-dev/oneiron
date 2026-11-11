//! The side tables `inbox` keeps (core split slice 1): each row declares one, and the crate's
//! build script places it in `side_table`'s catalogue.

crate::side_table::side_tables! {
    /// Owner-set inbox review dial (exceptions-only vs review-all), house per-feature dial pattern.
    /// Key: ().
    INBOX_REVIEW_DIAL: VaultMeta b"settings:inbox:v1:review_dial" Raw
        [restore: live] [family: unclassified] [tier: canonical];
}
