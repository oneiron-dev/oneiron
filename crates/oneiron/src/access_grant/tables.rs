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
    /// The companion profile grants by principal and PERSON (ARCH-0044 H424, census L3-28E):
    /// one empty row per ACCESS_GRANT row whose body is a live grant of CompanionProfile scope,
    /// any status. Key: id16 (principal) + id16 (PERSON) + id16 (grant).
    ACCESS_GRANT_COMPANION_INDEX: VaultMeta b"access-grant:companion:v1:" Raw
        [restore: not_imaged] [family: not_imaged] [tier: derived];
    /// The ACCESS_GRANT rows whose body no grant decoder reads, beside the index above: the
    /// walks fail closed on one, so its reads walk while one is stored. Key: id16 (grant).
    ACCESS_GRANT_COMPANION_INDEX_UNDECODABLE: VaultMeta b"access-grant:companion-undecodable:v1:" Raw
        [restore: not_imaged] [family: not_imaged] [tier: derived];
    /// Completeness flag of the index above (u64 version). Key: ().
    ACCESS_GRANT_COMPANION_INDEX_STATE: VaultMeta b"access-grant:companion-state:v1" Raw
        [restore: not_imaged] [family: not_imaged] [tier: derived];
}
