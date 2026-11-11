//! The side tables `secret_record` keeps (core split slice 1): each row declares one, and the crate's
//! build script places it in `side_table`'s catalogue.

crate::side_table::side_tables! {
    /// A carrier row the historical lift sweep marked (OF-067): the bytes it marked, by their
    /// hash, the detector's reason and the parts its readers withhold. The carrier keeps its
    /// bytes. Holds no value. Key: the carrier table's name, a colon, then its row key.
    SECRET_LIFT_MARK: VaultMeta b"secret_lift:mark:v1:" Named Engine
        [restore: content] [family: unclassified] [tier: canonical];
}
