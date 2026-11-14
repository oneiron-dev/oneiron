//! The side table the learned phonetic rung keeps (CROSS-ARCH-0013 rung 2): the crate's build
//! script places it in `side_table`'s catalogue.

crate::side_table::side_tables! {
    /// One learned phonetic vector per entity name: the model key (BLAKE3-16 of the model id and
    /// its width), then the v1 vector row. A derived index of the names, as the code postings
    /// are: no image carries it, and the reconcile pass embeds the names again. Key: id16 +
    /// name BLAKE3-16.
    PHONETIC_LEARNED_VECTOR: VaultMeta b"phonetic/learned_vector/" Raw
        [restore: not_imaged] [family: not_imaged] [tier: derived];
}
