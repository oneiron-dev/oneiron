//! The side tables `disclosure` keeps (core split slice 1): each row declares one, and the crate's
//! build script places it in `side_table`'s catalogue.

crate::side_table::side_tables! {
    /// Owner's model-channel band ceiling, optionally specialized by data class.
    /// Key: connection "/" class (or "*").
    DISCLOSURE_MODEL_CEILING: VaultMeta b"disclosure.model_ceiling.v1:" Named
        [restore: live] [family: unclassified] [tier: canonical];
    /// Enforcement-truth per-counterparty-contact disclosure scope row (rmpv-encoded), dual-written
    /// with an owner-visible claim. Key: id16.
    DISCLOSURE_SCOPE: VaultMeta b"disclosure.scope.v1:" Raw
        [restore: refuse "disclosure scopes"] [family: unclassified] [tier: canonical];
    /// Owner Tier-A mark row for an entity (value = marked_at u64 LE), dual-written with an owner-
    /// visible claim. Key: id16.
    DISCLOSURE_TIER_A: VaultMeta b"disclosure.tier_a.v1:" Raw
        [restore: refuse "disclosure scopes"] [family: unclassified] [tier: canonical];
}
