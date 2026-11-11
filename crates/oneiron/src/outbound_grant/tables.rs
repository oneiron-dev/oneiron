//! The side tables `outbound_grant` keeps (core split slice 1): each row declares one, and the crate's
//! build script places it in `side_table`'s catalogue.

crate::side_table::side_tables! {
    /// Per-envelope usage/rate-window accounting shared by every standing grant naming that envelope.
    /// Key: bytes (channel-identity envelope ref).
    OUTBOUND_GRANT_CHANNEL_IDENTITY_USAGE: VaultMeta b"outbound_grant:channel_identity_usage:v1:" Raw
        [restore: live] [family: unclassified] [tier: canonical];
}
