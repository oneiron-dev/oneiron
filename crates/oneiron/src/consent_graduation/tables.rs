//! The side tables `consent_graduation` keeps (core split slice 1): each row declares one, and the crate's
//! build script places it in `side_table`'s catalogue.

crate::side_table::side_tables! {
    /// Scope self-demotion log. Key: u64be + id16.
    RAMP_DEMOTION: VaultMeta b"ramp_demote:v1:" Named;
    /// Clean-streak floor override. Key: id16.
    RAMP_FLOOR: VaultMeta b"ramp_floor:v1:" Raw;
    /// Door-recorded ruling log. Key: u64be + id16.
    RAMP_OUTCOME: VaultMeta b"ramp_outcome:v1:" Named;
    /// Per-scope outcome statistics. Key: id16.
    RAMP_STATS: VaultMeta b"ramp_stats:v1:" Named;
}
