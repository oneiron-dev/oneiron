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
    /// One head row per pack of the default layer: the digest of the defaults the pack door last
    /// weighed, the keys the vault accepted from the pack, and the loose defaults that wait on a
    /// holder's yes (DESIGN 1.5 "Packs: a default that changes"). Key: the pack's name.
    SETTING_PACK_HEAD: VaultMeta b"setting:pack_head:v1:" Named
        [restore: live] [family: unclassified] [tier: canonical];
    /// One row per setting row the signed acts name, once the projection wrote it from them
    /// (stage 7a-2, DESIGN 1.6 "The fold and the projection"): the row's key, the act
    /// revision it was projected from, and how its acts stand. A pass that finds the same
    /// revision writes nothing. Key: the row's act target (16 bytes).
    SETTING_PROJECTION: VaultMeta b"setting:projection:v1:" Named
        [restore: live] [family: unclassified] [tier: canonical];
}
