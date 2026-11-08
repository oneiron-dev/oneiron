//! The side tables `persona_snapshot` keeps (core split slice 1): each row declares one, and the crate's
//! build script places it in `side_table`'s catalogue.

crate::side_table::side_tables! {
    /// Accepted persona copy and curation for an immutable mode-A export. Key: id16(export).
    PERSONA_SNAPSHOT_COPY: VaultMeta b"persona_snapshot:copy:v1:" Named Authored [accepts: crate::persona_snapshot::persona_snapshot_copy_accepts_masked]
        [restore: content] [family: unclassified] [tier: canonical];
    /// Durable handle for one named (agent, world) companion standing-context block. Key: hex64
    /// (blake3 of prefix+agent+world).
    STANDING_BLOCK: VaultMeta b"standing.block.v1:" LegacyJson
        [restore: refuse "standing blocks"] [family: unclassified] [tier: canonical];
}
