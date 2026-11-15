//! The side tables of the Schedule primitive: each row declares one, and the crate's build script
//! places it in `side_table`'s catalogue.

crate::side_table::side_tables! {
    /// One armed job: its trigger, who armed it, when it is next due, its last finish, a start
    /// marker while a run is in flight, its failures in a row, an owner's "run now", and the
    /// cursor of an unfinished run. Key: the job's code, 0x00, the subject's 16 bytes (none for
    /// a job about nothing).
    SCHEDULE: VaultMeta b"schedule:row:v1:" Named
        [restore: live] [family: unclassified] [tier: canonical]
        => crate::schedule::erase_schedule_actor_in_txn;
    /// The armed jobs in due order, derived from `SCHEDULE` in the same transaction; a restore
    /// rebuilds it and never carries a stale due time. Key: u64be (due), then `SCHEDULE`'s key.
    SCHEDULE_DUE: VaultMeta b"schedule:due:v1:" Named
        [restore: not_imaged] [family: not_imaged] [tier: derived];
}
