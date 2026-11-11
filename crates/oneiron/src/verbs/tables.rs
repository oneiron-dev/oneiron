//! The side tables `verbs` keeps (core split slice 1): each row declares one, and the crate's
//! build script places it in `side_table`'s catalogue.

crate::side_table::side_tables! {
    /// The erase previews a caller was shown and may still confirm (FIX
    /// 12522): the digest the preview showed, and when it was issued and
    /// expires on the vault's recording clock. Key: id16 (caller) + id16
    /// (record).
    ERASE_PREVIEW: VaultMeta b"erase:preview:v1:" Named
        [restore: live] [family: unclassified] [tier: canonical]
        => crate::verbs::erase_preview_actor_in_txn;
}
