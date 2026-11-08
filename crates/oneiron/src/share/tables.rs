//! The side tables `share` keeps (core split slice 1): each row declares one, and the crate's
//! build script places it in `side_table`'s catalogue.

crate::side_table::side_tables! {
    /// Local, engine-written provenance and monotonic revocation latch for one admitted brief share
    /// (issuer, gate decision id, effect-target digest, revocation state), proving the row was
    /// created through the share door and not a generic grant write. Key: id16.
    SHARE_BRIEF_ADMISSION: VaultMeta b"share:brief:admission:v1:" Raw
        [restore: refuse "share admissions"] [family: unclassified] [tier: canonical]
        => crate::share::erase_admission_actor_in_txn;
    /// One-way deletion fence for a brief identity. Key: id16; value: the one-byte marker `1`.
    SHARE_BRIEF_DELETE_RESERVATION: VaultMeta b"share:brief:deleting:v1:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
}
