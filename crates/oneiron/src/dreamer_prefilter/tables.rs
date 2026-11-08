//! The side tables `dreamer_prefilter` keeps (core split slice 1): each row declares one, and the crate's
//! build script places it in `side_table`'s catalogue.

crate::side_table::side_tables! {
    /// Dreamer prefilter screening policy. Key: ().
    PREFILTER_CONFIG: VaultMeta b"dreamer:prefilter:config:v1" Named;
    /// Turn to screening round index. Key: string ":" id16.
    PREFILTER_MEMBER: VaultMeta b"dreamer:prefilter:member:v1:" Raw;
    /// Prefilter round rollup. Key: bytes32.
    PREFILTER_ROUND: VaultMeta b"dreamer:prefilter:round:v1:" Named;
    /// Prefilter skip receipt. Key: bytes32 + id16.
    PREFILTER_SKIP: VaultMeta b"dreamer:prefilter:skip:v1:" Named;
}
