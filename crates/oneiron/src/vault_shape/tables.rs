//! The side tables `vault_shape` keeps (core split slice 1): each row declares one, and the crate's
//! build script places it in `side_table`'s catalogue.

crate::side_table::side_tables! {
    /// One vault shape apply's journal (ARCH-0070): its plan items and how each landed, so a torn
    /// apply resumes. Key: string (the plan's frontier, hex).
    VAULT_SHAPE_APPLY: VaultMeta b"vault_shape:apply:v1:" Named
        [restore: content] [family: unclassified] [tier: canonical];
    /// One entity kind's wire declaration as a vault shape apply landed it (ARCH-0070, FIX 2300):
    /// whether the kind is declared on the wire, by whom and when. Key: string (the kind's name).
    VAULT_SHAPE_WIRE: VaultMeta b"vault_shape:wire:v1:" Named
        [restore: content] [family: unclassified] [tier: canonical];
}
