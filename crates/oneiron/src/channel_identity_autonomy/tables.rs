//! The side tables `channel_identity_autonomy` keeps (core split slice 1): each row declares one, and the crate's
//! build script places it in `side_table`'s catalogue.

crate::side_table::side_tables! {
    /// Channel-identity autonomy modes, envelopes, graduation evidence and posting heads. Key:
    /// predicate `:` + subject.
    CHANNEL_IDENTITY_AUTONOMY: VaultMeta b"channel_identity_autonomy:v1:" Raw
        [restore: live] [family: unclassified] [tier: canonical];
}
