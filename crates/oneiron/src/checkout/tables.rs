//! The side tables `checkout` keeps (core split slice 1): each row declares one, and the crate's
//! build script places it in `side_table`'s catalogue.

crate::side_table::side_tables! {
    /// Per-repository environment blueprint. Key: bytes32.
    CHECKOUT_ENV_BLUEPRINT: VaultMeta b"checkout:env_blueprint:v1:" VersionedNamed
        [restore: content] [family: unclassified] [tier: canonical];
    /// Checkout lease act. Key: hex32.
    CHECKOUT_LEASE: VaultMeta b"checkout:lease:v1:" Raw
        [restore: live] [family: unclassified] [tier: canonical];
    /// Checkout settlement receipt. Key: hex32 + decimal + hex64.
    CHECKOUT_SETTLEMENT: VaultMeta b"checkout:settlement:v1:" Raw
        [restore: live] [family: unclassified] [tier: canonical];
    /// Retired checkout epoch high-water mark. Key: hex32.
    CHECKOUT_TOMBSTONE: VaultMeta b"checkout:tombstone:v1:" Raw
        [restore: live] [family: unclassified] [tier: canonical];
}
