//! The side tables `failure_ladder` keeps (core split slice 1): each row declares one, and the crate's
//! build script places it in `side_table`'s catalogue.

crate::side_table::side_tables! {
    /// Terminal custom-agent dispatch failure classification. Key: id16(attempt).
    CUSTOM_AGENT_FAILURE: VaultMeta b"custom-agent:failure:v1:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Durable failure-ladder case authenticating one healer admission, bound to its lease-fenced
    /// failed attempt. Key: hex32 (case_ref).
    HEALER_CASE: VaultMeta b"healer:case:v1:" Named
        [restore: content] [family: unclassified] [tier: canonical];
}
