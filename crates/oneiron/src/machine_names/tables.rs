//! The side table `machine_names` keeps: each row declares one, and the crate's build script
//! places it in `side_table`'s catalogue.

crate::side_table::side_tables! {
    /// The owner's own name for one of his machines (FIX [DEVICE-DISPLAY-NAME]), admitted by the
    /// side-row wall, with the Gate receipt of the set that wrote it. Display only: outside the
    /// signed machine profile, and no authority, policy or routing code reads it. Key: id16 (the
    /// MACHINE row).
    MACHINE_OWNER_NAME: VaultMeta b"machine_name:owner:v1:" Named Authored [accepts: crate::machine_names::accepts_masked]
        [restore: live] [family: unclassified] [tier: canonical];

    /// The name and model each of the owner's machines reports for itself, as that machine dated
    /// them (Engine RULING MACHINE-NAMES-CARRIER = B): this install's own row follows its host's
    /// declaration, every other row came from the residence home. Display only, as the owner's
    /// name is. Key: id16 (the MACHINE row).
    MACHINE_REPORTED_NAME: VaultMeta b"machine_name:reported:v1:" Named Authored [accepts: crate::machine_names::exchange::accepts_masked_report]
        [restore: live] [family: unclassified] [tier: canonical];
}
