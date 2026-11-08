//! The side tables `channel_identity_selection` keeps (core split slice 1): each row declares one, and the crate's
//! build script places it in `side_table`'s catalogue.

crate::side_table::side_tables! {
    /// Channel-identity selection rule set. Key: ().
    CHANNEL_IDENTITY_SELECTION_RULES: VaultMeta b"channel_identity_selection:v1:rules" Raw
        [restore: live] [family: unclassified] [tier: canonical]
        => crate::channel_identity_selection::erase_rule_actor_in_txn;
}
