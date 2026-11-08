//! The side tables `access_grant` keeps (core split slice 1): each row declares one, and the crate's
//! build script places it in `side_table`'s catalogue.

crate::side_table::side_tables! {
    /// A pending cross-relationship access request awaiting the owner's approve/deny decision. Key:
    /// id16.
    ACCESS_REQUEST: VaultMeta b"access-request:v1:" LegacyJson
        [restore: content] [family: unclassified] [tier: canonical];
    /// The owner's grant/revoke act on an access grant in the commit that changed it
    /// (FIX 10980). Writer-trusted local receipt, not a signed op. Key: u64be(sequence).
    ACCESS_GRANT_OWNER_ACT: VaultMeta b"settings:owner_act_access_grant:v1:" Named
        [restore: live] [family: unclassified] [tier: canonical];
}
