//! The side tables `skill_scan` keeps (core split slice 1): each row declares one, and the crate's
//! build script places it in `side_table`'s catalogue.

crate::side_table::side_tables! {
    /// Persisted activation-risk threshold dial for skill-scan consent escalation. Key: ().
    SKILL_SCAN_ACTIVATION_RISK_THRESHOLD: VaultMeta b"settings:skill_scan:v1:activation_risk_threshold" Raw
        [restore: live] [family: unclassified] [tier: canonical];
}
