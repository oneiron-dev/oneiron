//! The side tables `agent_def` keeps (core split slice 1): each row declares one, and the crate's
//! build script places it in `side_table`'s catalogue.

crate::side_table::side_tables! {
    /// Binds a captured-source ASSET id back to the child agent it was birthed for. Key: id16.
    AGENT_DEF_BIRTH_ASSET_BINDING: VaultMeta b"agent_def/birth-asset-binding/v1\0" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Empty marker: a captured dependency input has been retired. Key: id16.
    AGENT_DEF_BIRTH_INPUT_RETIRED: VaultMeta b"agent_def/birth-input-retired/v1\0" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Empty marker: an agent's birth source has been retired. Key: id16.
    AGENT_DEF_BIRTH_RETIRED: VaultMeta b"agent_def/birth-retired/v1\0" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// What an agent id answers to on every later put, across a delete: the widest ceiling a
    /// row at the id may hold (one byte, 0 proposed, 1 auto), then the 16-byte parent row it was
    /// born forked from, if any. Key: id16.
    AGENT_DEF_ID_PIN: VaultMeta b"agent_def/id-pin/v1\0" Raw
        [restore: live] [family: unclassified] [tier: canonical];
    /// Frozen source-tree identity (source id + skill content hash, 48 raw bytes) recorded at an
    /// agent's genuine local birth. Key: id16.
    AGENT_DEF_PORTABLE_BIRTH: VaultMeta b"agent_def/portable-birth/v1\0" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// FIX 4472: the model an agent's last wake ran on, so a wake on another model notes it in
    /// the agent's own diary. Key: id16(agent).
    AGENT_DEF_WAKE_MODEL: VaultMeta b"agent_def/wake-model/v1\0" Named
        [restore: content] [family: unclassified] [tier: canonical];
    /// Pre-1890 reserved-actor census row, deleted with the census it served; not written by current
    /// code, only deleted once on seed. Key: ().
    AGENT_DEF_DEFAULT_RESERVED_ACTOR_CENSUS_V1: VaultMeta b"agent_def:default_reserved_actor_census:v1" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Pre-1890 reserved-actor census row, deleted with the census it served; not written by current
    /// code, only deleted once on seed. Key: ().
    AGENT_DEF_RESERVED_ACTOR_CENSUS_V2: VaultMeta b"agent_def:reserved_actor_census:v2" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Legacy pre-1890 per-vault system-agent enable toggle (single byte 0x00/0x01), consumed once
    /// and deleted by the manifest seeder. Key: string.
    AGENT_DEF_SYSTEM_TOGGLE_LEGACY: VaultMeta b"agent_def:system_toggle:v1:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
}
