//! The side tables `dreamer_tournament` keeps (core split slice 1): each row declares one, and the crate's
//! build script places it in `side_table`'s catalogue.

crate::side_table::side_tables! {
    /// Per-round branch tournament evidence row (verdict, synthesis/critique/veto artifact ids) for
    /// one candidate. Key: u16be+string(run_id) + id16 + u16be + u8 + u16be+string(candidate_ref).
    DREAMER_TOURNAMENT_EVIDENCE: VaultMeta b"dreamer:tournament:v1:" Named
        [restore: content] [family: unclassified] [tier: canonical];
}
