//! The side tables `dispatch_byoa` keeps (core split slice 1): each row declares one, and the crate's
//! build script places it in `side_table`'s catalogue.

crate::side_table::side_tables! {
    /// A native terminal capture's artifact, version, claim and hash. Key: attempt16.
    BYOA_EXHAUST_CAPTURE: VaultMeta b"byoa:exhaust_capture:v1:" Named
        [restore: content] [family: structure] [tier: canonical];
    /// A staged-job artifact erase owed after its legal hold lifts. Key: hash32 (job digest).
    BYOA_STAGED_INPUT_ERASE: VaultMeta b"byoa:staged_input_erase:v1:" Named
        [restore: content] [family: unclassified] [tier: canonical];
}
