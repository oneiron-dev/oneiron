//! The side tables `policy_setting_doors` keeps (core split slice 1): each row declares one, and the crate's
//! build script places it in `side_table`'s catalogue.

crate::side_table::side_tables! {
    /// The owner's act on a vault-wide setting (the dreamer's wake policy, the inference
    /// defaults), recorded in the commit that changed it (WILL-PLAN L13 row 01). Key:
    /// u64be(sequence).
    POLICY_SETTING_ACT: VaultMeta b"settings:owner_act:v1:" Named
        [restore: live] [family: unclassified] [tier: canonical];
}
