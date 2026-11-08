//! The side tables `saved_query` keeps (core split slice 1): each row declares one, and the crate's
//! build script places it in `side_table`'s catalogue.

crate::side_table::side_tables! {
    /// Node-local fast-path watermark (epoch u64be + content digest) for one (query, entity) pair's
    /// last-applied membership epoch. Key: id16 + id16.
    SAVED_QUERY_WATERMARK: VaultMeta b"saved_query.epoch.v1:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Durable append-only membership-transition event history for one (query, entity) pair, keyed by
    /// epoch. Key: id16 + id16 + u64be. Encoded as hand-rolled CANONICAL JSON (sorted object keys),
    /// not a plain derive, so the codec is `Raw` rather than `LegacyJson`.
    SAVED_QUERY_MEMBERSHIP_EVENT: VaultMeta b"saved_query.event.v1:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Operator-supplied predicate rewrite map for one compliance/definition pack move
    /// (from_pack@from_version->to_pack@to_version). Key: string "@" string "->" string "@" string.
    SAVED_QUERY_PACK_MIGRATION_MAP: VaultMeta b"saved_query.packmap.v1:" LegacyJson
        [restore: content] [family: unclassified] [tier: canonical];
    /// Receipt of one pack-drift repair action (auto-migration, rewrite proposal, or pause) taken
    /// against a saved query. Key: id16. Encoded as hand-rolled CANONICAL JSON (sorted object keys),
    /// not a plain derive, so the codec is `Raw` rather than `LegacyJson`.
    SAVED_QUERY_REPAIR: VaultMeta b"saved_query.repair.v1:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
}
