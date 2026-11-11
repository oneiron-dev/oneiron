//! The side tables `git_wire` keeps (core split slice 1): each row declares one, and the crate's
//! build script places it in `side_table`'s catalogue.

crate::side_table::side_tables! {
    GIT_WIRE_RECORD: VaultMeta b"git_wire:record:v2:" Named
        [restore: content] [family: unclassified] [tier: canonical];
}
