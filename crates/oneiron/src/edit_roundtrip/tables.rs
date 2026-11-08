//! The side tables `edit_roundtrip` keeps (core split slice 1): each row declares one, and the crate's
//! build script places it in `side_table`'s catalogue.

crate::side_table::side_tables! {
    /// The creation record of one deck made from a kept outline: born-from, template, slides,
    /// write set and fit. Key: id16 (artifact).
    DECK_CREATION: VaultMeta b"deck:creation:v1:" Named
        [restore: content] [family: unclassified] [tier: canonical];
    /// The design directions compiled from one kept outline. Key: id16 (outline note).
    DECK_DESIGN_SPEC: VaultMeta b"deck:design_spec:v1:" Named
        [restore: content] [family: unclassified] [tier: canonical];
    /// A person's keep of one outline brief: frontier, exact bytes and hash. Key: id16 (note).
    DECK_OUTLINE_KEEP: VaultMeta b"deck:outline_keep:v1:" Named
        [restore: content] [family: unclassified] [tier: canonical];
}
