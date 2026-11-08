//! The side tables `source_audience` keeps (core split slice 1): each row declares one, and the crate's
//! build script places it in `side_table`'s catalogue.

crate::side_table::side_tables! {
    /// A row a source landing is about to stamp with the source-audience obligation in its own
    /// write (fix list row 16256): the one mark the write door admits the stamp under. Binding the
    /// row takes it away, and the landing commits with none left, so a row never outlives its
    /// transaction here. Key: id16(row).
    SOURCE_AUDIENCE_BIRTH: VaultMeta b"source_audience:birth:v1:" Named;
    /// The policies a row written from source-bound rows reads under beside its own lineage, the
    /// union of every set a full-window carrier brought (fix list row 17207). It only grows.
    /// Key: id16(row).
    SOURCE_AUDIENCE_DERIVED: VaultMeta b"source_audience:derived:v1:" Named;
    /// One change to a source audience's readers, its receipt (FIX 12559); the policy entry's
    /// scrub forgets an erased actor here too. Key: id16(policy) + u64be revision.
    SOURCE_AUDIENCE_EVENT: VaultMeta b"source_audience:event:v1:" Named;
    /// A row this vault reads to no one meanwhile (FIX 12559 follow-up): its carried binding
    /// waits for its policy, or the vault it came from withheld it after it travelled. Key:
    /// id16(row).
    SOURCE_AUDIENCE_HELD: VaultMeta b"source_audience:held:v1:" Named;
    /// Whether a row a source landed was ever written here, by any door (fix list row 16255):
    /// until one is, no row's words came from one, and the source-audience walk answers at
    /// once. Key: ().
    SOURCE_AUDIENCE_LANDED: VaultMeta b"source_audience:landed:v1:seen" Named;
    /// One source audience: a mail or calendar source's readers, or one thread's shares (FIX
    /// 12559). An actor's scrub takes it out of every policy and event. Key: id16(policy).
    SOURCE_AUDIENCE_POLICY: VaultMeta b"source_audience:policy:v1:" Named
        => crate::source_audience::erase_actor_in_txn;
    /// A changed source audience's pending wake of the windows it rides (fix list row 17203):
    /// its generation and the last window the live mirror's drain took. Key: id16(policy).
    SOURCE_AUDIENCE_POLICY_WAKE: VaultMeta b"source_audience:policy_wake:v1:" Named;
    /// A window that carries a source audience policy, as its last export or persist found it
    /// (fix list row 17203): the window's label. Key: id16(policy) + blake3 (32) of the label.
    SOURCE_AUDIENCE_POLICY_WINDOW: VaultMeta b"source_audience:policy_window:v1:" Named;
    /// The source audience a row was born under; it never moves (FIX 12559). Key: id16(row).
    SOURCE_AUDIENCE_RECORD: VaultMeta b"source_audience:record:v1:" Named;
    /// One source thread's audience policy (FIX 12559). Key: id16(source policy) + blake3 (32)
    /// of the source's thread key.
    SOURCE_AUDIENCE_THREAD: VaultMeta b"source_audience:thread:v1:" Named;
}
