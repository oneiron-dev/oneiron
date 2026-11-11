//! The side tables `commitment_wake` keeps (core split slice 1): each row declares one, and the crate's
//! build script places it in `side_table`'s catalogue.

crate::side_table::side_tables! {
    /// Where the owner's own commitment reminders go, and the owner's civil
    /// clock for their delivery windows (OF-187). Key: ().
    COMMITMENT_REMINDER_ROUTE: VaultMeta b"commitment_reminder_route:v1" Named
        [restore: live] [family: unclassified] [tier: canonical];
}
