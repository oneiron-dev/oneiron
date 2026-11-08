//! The side tables `channel_identity` keeps (core split slice 1): each row declares one, and the crate's
//! build script places it in `side_table`'s catalogue.

crate::side_table::side_tables! {
    /// Two-slot channel assignment index: occupant id16 then predecessor id16, all-zero for an
    /// empty slot. Key: bytes32 (blake3 of the length-framed channel and address).
    CHANNEL_IDENTITY_ASSIGNMENT: VaultMeta b"cid_assign:v1:" Raw
        [restore: live] [family: unclassified] [tier: canonical];
    /// Deletion evidence (the single byte 1) for a soft-erased channel identity's retained
    /// header-only shell, staged with slot removal. Key: id16.
    CHANNEL_IDENTITY_ASSIGNMENT_ERASED: VaultMeta b"cid_assign_erased:v1:" Raw
        [restore: live] [family: unclassified] [tier: canonical];
}
