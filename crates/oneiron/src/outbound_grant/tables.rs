//! The side tables `outbound_grant` keeps (core split slice 1): each row declares one, and the crate's
//! build script places it in `side_table`'s catalogue.

crate::side_table::side_tables! {
    /// Per-envelope usage/rate-window accounting shared by every standing grant naming that envelope.
    /// Key: bytes (channel-identity envelope ref).
    OUTBOUND_GRANT_CHANNEL_IDENTITY_USAGE: VaultMeta b"outbound_grant:channel_identity_usage:v1:" Raw
        [restore: live] [family: unclassified] [tier: canonical];
    /// The standing outbound grants by grant id (census L3-28A): one empty row per standing
    /// consent Grant row that is an outbound grant. Key: id16 (grant id) + string (the Grant row's
    /// reference, hex64).
    OUTBOUND_GRANT_ID_INDEX: VaultMeta b"outbound_grant/id/v1\0" Raw
        [restore: not_imaged] [family: not_imaged] [tier: derived];
    /// The standing outbound grants by principal (ARCH-0044 H424, census L3-28A): one empty row
    /// per standing consent Grant row that is an outbound grant. Key: bytes32 (blake3 of the
    /// principal reference) + id16 (grant id) + string (the Grant row's reference, hex64).
    OUTBOUND_GRANT_PRINCIPAL_INDEX: VaultMeta b"outbound_grant/principal/v1\0" Raw
        [restore: not_imaged] [family: not_imaged] [tier: derived];
    /// Completeness flag of the two outbound grant indexes above (u64 version). Key: ().
    OUTBOUND_GRANT_INDEX_STATE: VaultMeta b"outbound_grant/index_state/v1" Raw
        [restore: not_imaged] [family: not_imaged] [tier: derived];
}
