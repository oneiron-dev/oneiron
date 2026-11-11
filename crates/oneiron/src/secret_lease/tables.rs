//! The side tables `secret_lease` keeps (core split slice 1): each row declares one, and the crate's
//! build script places it in `side_table`'s catalogue.

crate::side_table::side_tables! {
    /// T1/T2 secret-materialization lease row (escalation ladder to local registration). Key:
    /// hex32(lease id).
    SECRET_LEASE: VaultMeta b"secret_lease:v1:" Raw
        [restore: live] [family: unclassified] [tier: canonical]
        => crate::secret_lease::erase_lease_actor_in_txn;
    /// A value-free grant a secret lease's holder redeems (FIX 4313): the custody record, the
    /// value generation it pins, the holder principal and run, the effector, the target and the
    /// expiry, and for a T1/T2 grant the lease it rides. Key: id16 (grant id).
    SECRET_LEASE_GRANT: VaultMeta b"secret_lease_grant:v1:" Named Engine
        [restore: live] [family: unclassified] [tier: canonical]
        => crate::secret_lease::erase_secret_grant_actor_in_txn;
    /// Durable receipt written before a secret value is returned from materialization. Key:
    /// hex32(receipt id).
    SECRET_MATERIALIZATION_RECEIPT: VaultMeta b"secret_lease_receipt:v1:" Raw
        [restore: live] [family: unclassified] [tier: canonical]
        => crate::secret_lease::erase_receipt_actor_in_txn;
    /// T2 local-file registration for a materialized secret, read wholesale for snapshot exclusion.
    /// Key: hex32(lease id).
    SECRET_LOCAL_REGISTRATION: VaultMeta b"secret_local:v1:" Raw
        [restore: live] [family: unclassified] [tier: canonical];
}
