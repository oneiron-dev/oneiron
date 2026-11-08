//! The side tables `settings` keeps (core split slice 1): each row declares one, and the crate's
//! build script places it in `side_table`'s catalogue.

crate::side_table::side_tables! {
    /// The owner's backup setting (FIX 5621): whether a running server backs up on its own, the
    /// hours between and the newest kept, one row for the whole choice. Absent is no choice, and
    /// the deployment's `[backup]` section decides. Key: ().
    BACKUP_POLICY: VaultMeta b"settings:backup:v1:policy" Named
        [restore: live] [family: unclassified] [tier: canonical];
    /// The owner's board layout settings (BOARD-LAYOUT): the board cap, the default layout an
    /// agent's board renders under until it lays out its own, and the override whose sections win
    /// over every agent's own. Absent reads empty. Key: ().
    BOARD_LAYOUT_SETTINGS: VaultMeta b"settings:board_layout:v1" Named
        [restore: live] [family: unclassified] [tier: canonical]
        => crate::settings::board_layout::erase_board_layout_agent_override_in_txn;
    /// One client-readable customization-settings change-notification event. Key: u64be (sequence).
    CUSTOMIZATION_EVENT: VaultMeta b"settings:customization:v1:event:" Named Authored [accepts: crate::settings::customization_event_accepts_masked]
        [restore: live] [family: unclassified] [tier: canonical];
    /// Monotonic sequence counter for customization change-notification events. Key: ().
    CUSTOMIZATION_EVENT_SEQUENCE: VaultMeta b"settings:customization:v1:event_sequence" Raw
        [restore: live] [family: unclassified] [tier: canonical];
    /// Persisted four-layer (accent/type/mode/world) client customization profile. Key: ().
    CUSTOMIZATION_SETTINGS: VaultMeta b"settings:customization:v1:profile" Named Authored [accepts: crate::settings::customization_settings_accepts_masked]
        [restore: live] [family: unclassified] [tier: canonical];
    /// Owner on/off dial for proactive Dreamer plugin suggestions. Key: ().
    PLUGIN_SUGGESTIONS_ENABLED: VaultMeta b"settings:dreamer:v1:plugin_suggestions_enabled" Raw
        [restore: live] [family: unclassified] [tier: canonical];
    /// The owner's standing quota fallback for one model offer (OF-305): the engine model id its
    /// calls go to while the offer is parked, set by a `use_fallback` answer. Owner policy, kept
    /// apart from the deployment's runtime cooldowns. Key: hex64 (the offer's cooldown key).
    MODEL_OWNER_FALLBACK: VaultMeta b"settings:models:v1:fallback:" Raw Authored [accepts: crate::settings::model_owner_fallback_accepts_masked]
        [restore: live] [family: unclassified] [tier: canonical];
    /// The owner's Responses `store` switch (OF-602): on, a provider keeps each response and a
    /// reconnected socket resumes the chain. Absent is off. Key: ().
    MODEL_OWNER_RESPONSES_STORE: VaultMeta b"settings:models:v1:responses_store" Named
        [restore: live] [family: unclassified] [tier: canonical];
    /// The owner's switch over an Admin deleting a private room thread (FIX 6382): `false` turns
    /// it off. Absent is on. Key: ().
    ROOM_THREADS_ADMIN_DELETE: VaultMeta b"settings:rooms:v1:admin_delete" Named
        [restore: live] [family: unclassified] [tier: canonical];
    /// The owner's switch over an Admin walking into a private room thread (FIX 6382): `false`
    /// turns it off. Absent is on. Key: ().
    ROOM_THREADS_ADMIN_WALK_IN: VaultMeta b"settings:rooms:v1:admin_walk_in" Named
        [restore: live] [family: unclassified] [tier: canonical];
}
