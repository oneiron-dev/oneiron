//! The side tables `batch::export` keeps: the inert retained copies of archived
//! source-table rows. Each row declares one table, and the crate's build script places it in
//! `side_table`'s catalogue.

crate::side_table::side_tables! {
    /// Inert retained copies of whole-vault archive source rows (SIDE-1): each row keeps its
    /// source table's name with the row's original key suffix and value bytes. Vault-wide; no
    /// live reader reads these rows, and the next archive carries them again. Key: the 32-byte
    /// identity hash of the length-framed (table, source key, blake3(value)) triple.
    ARCHIVE_RETAINED_SIDE_ROW: VaultMeta b"archive:retained_side_row:v1:" Named Admitted
        [restore: content] [family: unclassified] [tier: canonical]
        => crate::batch::export::archive_retained_side_rows::erase_retained_side_row_actor_in_txn;
}
