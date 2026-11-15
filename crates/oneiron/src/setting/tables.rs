//! The side tables of the Setting primitive: each row declares one, and the crate's build script
//! places it in `side_table`'s catalogue.

crate::side_table::side_tables! {
    /// One setting row: a key's value or the owner's pin at one scope, for a key whose choice the
    /// live vault keeps through a restore (`restore: live`, the default). Key: the key name, 0x00,
    /// the item, 0x00, the mode byte and the scope (`oneiron_setting_contract::RowKey`).
    SETTING: VaultMeta b"setting:row:v1:" Named
        [restore: live] [family: unclassified] [tier: canonical]
        => crate::setting::erase_setting_row_actor_in_txn;
    /// The same rows for a key whose choice is part of what records mean, so it travels with them
    /// through a restore (`restore: content`). Key: as `SETTING`'s.
    SETTING_CONTENT: VaultMeta b"setting:content:v1:" Named
        [restore: content] [family: unclassified] [tier: canonical]
        => crate::setting::erase_setting_content_actor_in_txn;
    /// Every setting change, written in the commit that makes it: who, in which capacity, the
    /// prior value and the new one. The `settings` change feed reads it. Key: u64be (sequence).
    SETTING_CHANGE: VaultMeta b"setting:change:v1:" Named
        [restore: live] [family: unclassified] [tier: canonical]
        => crate::setting::erase_setting_change_actor_in_txn;
    /// The last setting change sequence handed out, so a scrubbed row's sequence is never handed
    /// out again under a feed cursor. Key: ().
    SETTING_CHANGE_NEXT: VaultMeta b"setting:change_next:v1" Named
        [restore: live] [family: unclassified] [tier: canonical];
}
