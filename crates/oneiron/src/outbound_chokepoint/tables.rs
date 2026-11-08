//! The side tables `outbound_chokepoint` keeps (core split slice 1): each row declares one, and the crate's
//! build script places it in `side_table`'s catalogue.

crate::side_table::side_tables! {
    /// Hash of semantic send key -> (intent id hash32, reservation timestamp u64be). Key: hash32.
    OUTBOUND_DEDUPE_RESERVATION: VaultMeta b"outbound:dedupe:v1:" Raw
        [restore: live] [family: unclassified] [tier: canonical];
    /// Intent id -> semantic send key's full `outbound:dedupe:v1:` key. Key: hash32.
    OUTBOUND_DEDUPE_INTENT: VaultMeta b"outbound:dedupe_intent:v1:" Raw
        [restore: live] [family: unclassified] [tier: canonical];
}
