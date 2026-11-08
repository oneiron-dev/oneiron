//! The side tables `learning_setting` keeps (core split slice 1): each row declares one, and the crate's
//! build script places it in `side_table`'s catalogue.

crate::side_table::side_tables! {
    /// Owner seed or pin over one learned-setting catalog row (value, weight in runs, setter, why).
    /// Key: string (setting key "\0" mode).
    LEARNING_SETTING: VaultMeta b"learning:setting:v1:" Raw
        [restore: live] [family: unclassified] [tier: canonical]
        => crate::learning_setting::erase_setting_actor_in_txn;
}
