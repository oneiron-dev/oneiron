//! The side tables `learning_setting_choice` keeps (core split slice 1): each row declares one, and the crate's
//! build script places it in `side_table`'s catalogue.

crate::side_table::side_tables! {
    /// Owner seed or pin over one spawn choice (model, width, pattern or budget) at a goal, a
    /// project, a task type or the vault (value, weight in runs, setter, why). Key: string (choice
    /// "\0" mode, then the scope).
    LEARNING_CHOICE: VaultMeta b"learning:choice:v1:" Raw
        [restore: live] [family: unclassified] [tier: canonical]
        => crate::learning_setting_choice::erase_choice_actor_in_txn;
}
