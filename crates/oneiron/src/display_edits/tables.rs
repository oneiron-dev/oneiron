//! The side table `display_edits` keeps: each row declares one, and the crate's build script
//! places it in `side_table`'s catalogue.

crate::side_table::side_tables! {
    /// One agent's open proposal of a display edit the owner answers (FIX
    /// [SECRETS-LABEL-PURPOSE-VERBS], [DEVICE-DISPLAY-NAME]; Engine RULING
    /// DISPLAY-EDIT-PROPOSAL-SCOPE = A): a secret's label or purpose, or a machine's name, with the
    /// agent's why and the inbox Asks it raised. An answer, a newer proposal of the agent's for the
    /// same edit, or the agent's erase deletes it. Its text was scanned before it landed; it holds
    /// no value. Key: id16 (the proposal).
    DISPLAY_EDIT_PROPOSAL: VaultMeta b"display_edit:proposal:v1:" Named
        [restore: live] [family: unclassified] [tier: canonical]
        => crate::display_edits::erase_display_edit_actor_in_txn;
}
