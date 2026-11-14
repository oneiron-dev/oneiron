//! The side tables `verbs` keeps (core split slice 1): each row declares one, and the crate's
//! build script places it in `side_table`'s catalogue.

crate::side_table::side_tables! {
    /// The owner-checked previews a caller was shown and may still confirm
    /// (DEC-0006 #undo-class, FIX 12522 generalized): the verb previewed, and
    /// when it was issued and, for a kept row, expires on the vault's
    /// recording clock. Key: id16 (caller) + 32 (confirm digest).
    OWNER_CONFIRM_PREVIEW: VaultMeta b"owner_confirm:preview:v1:" Named
        [restore: live] [family: unclassified] [tier: canonical]
        => crate::verbs::owner_confirm_actor_in_txn;
}
