//! The side tables `secret_rotation` keeps (core split slice 1): each row declares one, and the crate's
//! build script places it in `side_table`'s catalogue.

crate::side_table::side_tables! {
    /// Forward sidecar of secret taint-refs attached to one piece of build exhaust. Key: hex32(entity
    /// id).
    SECRET_EXHAUST_TAINT: VaultMeta b"secret_exhaust_taint:v1:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Durable attestation of one secret rotate-or-revoke op; carries no value bytes. Key:
    /// hex32(receipt id).
    SECRET_ROTATION_RECEIPT: VaultMeta b"secret_rotation_receipt:v1:" Raw
        [restore: live] [family: unclassified] [tier: canonical];
}
