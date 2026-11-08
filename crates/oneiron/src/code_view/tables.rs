//! The side tables `code_view` keeps (core split slice 1): each row declares one, and the crate's
//! build script places it in `side_table`'s catalogue.

crate::side_table::side_tables! {
    /// Cache-hit outcome record for one view's build/verify action, keyed by view id and action key.
    /// Key: id16 + bytes32 (view id then build action key).
    CODE_VIEW_BUILD: VaultMeta b"code_view:build:v1:" LegacyJson
        [restore: content] [family: unclassified] [tier: canonical];
    /// A materialized per-agent code view's receipt: fork hash plus the per-file content-hash
    /// manifest, keyed by view id. Key: id16.
    CODE_VIEW_RECEIPT: VaultMeta b"code_view:receipt:v1:" Named
        [restore: content] [family: unclassified] [tier: canonical];
}
