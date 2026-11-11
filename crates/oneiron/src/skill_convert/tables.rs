//! The side tables `skill_convert` keeps (core split slice 1): each row declares one, and the crate's
//! build script places it in `side_table`'s catalogue.

crate::side_table::side_tables! {
    /// Staleness note of a skill. Key: id16.
    SKILL_STALE_NOTE: VaultMeta b"skill_convert/stale_note/v1\0" Raw
        [restore: content] [family: unclassified] [tier: canonical];
}
