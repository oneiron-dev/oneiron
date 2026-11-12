//! The side tables `source_audience` keeps (core split slice 1): each row declares one, and the crate's
//! build script places it in `side_table`'s catalogue.

crate::side_table::side_tables! {
    /// A row a source landing is about to stamp with the source-audience obligation in its own
    /// write (fix list row 16256): the one mark the write door admits the stamp under. Binding the
    /// row takes it away, and the landing commits with none left, so a row never outlives its
    /// transaction here. Key: id16(row).
    SOURCE_AUDIENCE_BIRTH: VaultMeta b"source_audience:birth:v1:" Named
        // Restore class: A source landing's birth mark lives inside its own write and never commits
        // (fix list row 16256): runtime working state, which no image carries.
        [restore: not_imaged] [family: not_imaged] [tier: runtime];
    /// The policies a row written from source-bound rows reads under beside its own lineage, the
    /// union of every set a full-window carrier brought (fix list row 17207). It only grows.
    /// Key: id16(row).
    SOURCE_AUDIENCE_DERIVED: VaultMeta b"source_audience:derived:v1:" Named
        // Restore class: A change to a source's readers is history, restored with the rows it
        // admitted; the policy itself is live authority: a restore never gives back a reader
        // removed since, or takes away one added (FIX 12559). A derived row's carried policies
        // never shrink: a changed set for a row the image holds refuses the restore (FIX 17207). A
        // derived row's carried policies only ever grow (FIX 17207): a restore that would give back
        // a smaller set for a row the image holds refuses, so a reader one of the added policies
        // denies never reads the row again. The floor of a row made after the checkpoint leaves
        // with the row.
        [restore: refuse_image_entities "a derived row's carried policies"]
        [family: unclassified]
        [tier: canonical];
    /// One change to a source audience's readers, its receipt (FIX 12559); the policy entry's
    /// scrub forgets an erased actor here too. Key: id16(policy) + u64be revision.
    SOURCE_AUDIENCE_EVENT: VaultMeta b"source_audience:event:v1:" Named
        // Payload family: The source-audience policies, their events and the thread index stay
        // under the vault-wide seal until a per-owner compartment (row 17208).
        [restore: content] [family: unclassified] [tier: canonical];
    /// A row this vault reads to no one meanwhile (FIX 12559 follow-up): its carried binding
    /// waits for its policy, or the vault it came from withheld it after it travelled. Key:
    /// id16(row).
    SOURCE_AUDIENCE_HELD: VaultMeta b"source_audience:held:v1:" Named
        // Restore class: A held-back row stays denied in the image as it was.
        // Payload family: A row's source-audience binding and hold, each under the row its key
        // names (fix list row 17455). SOURCE_AUDIENCE_DERIVED stays in the image until its floor
        // check reads opened parts (fix list row 20941).
        [restore: content] [family: owner SourceAudience] [tier: canonical];
    /// Whether a row a source landed was ever written here, by any door (fix list row 16255):
    /// until one is, no row's words came from one, and the source-audience walk answers at
    /// once. Key: ().
    SOURCE_AUDIENCE_LANDED: VaultMeta b"source_audience:landed:v1:seen" Named
        // Restore class: Whether a source landed a row stands with the rows the image holds.
        [restore: content] [family: structure] [tier: canonical];
    /// One source audience: a mail or calendar source's readers, or one thread's shares (FIX
    /// 12559). An actor's scrub takes it out of every policy and event. Key: id16(policy).
    SOURCE_AUDIENCE_POLICY: VaultMeta b"source_audience:policy:v1:" Named
        // Payload family: The source-audience policies, their events and the thread index stay
        // under the vault-wide seal until a per-owner compartment (row 17208).
        [restore: live] [family: unclassified] [tier: canonical]
        => crate::source_audience::erase_actor_in_txn;
    /// A changed source audience's pending wake of the windows it rides (fix list row 17203):
    /// its generation and the last window the live mirror's drain took. Key: id16(policy).
    SOURCE_AUDIENCE_POLICY_WAKE: VaultMeta b"source_audience:policy_wake:v1:" Named
        // Restore class: A policy's pending wake and the windows it rides are this vault's own work
        // over its live policies and stored windows (fix list row 17203).
        // Payload family: A changed policy's wake and the windows it rides are a generation, a
        // window position and a window label: markers with no payload of their own.
        [restore: live] [family: structure] [tier: canonical];
    /// A window that carries a source audience policy, as its last export or persist found it
    /// (fix list row 17203): the window's label. Key: id16(policy) + blake3 (32) of the label.
    SOURCE_AUDIENCE_POLICY_WINDOW: VaultMeta b"source_audience:policy_window:v1:" Named
        // Payload family: A changed policy's wake and the windows it rides are a generation, a
        // window position and a window label: markers with no payload of their own.
        [restore: live] [family: structure] [tier: canonical];
    /// The source audience a row was born under; it never moves (FIX 12559). Key: id16(row).
    SOURCE_AUDIENCE_RECORD: VaultMeta b"source_audience:record:v1:" Named
        // Restore class: A row's birth binding stands with the row as the image holds it.
        // Payload family: A row's source-audience binding and hold, each under the row its key
        // names (fix list row 17455). SOURCE_AUDIENCE_DERIVED stays in the image until its floor
        // check reads opened parts (fix list row 20941).
        [restore: content] [family: owner SourceAudience] [tier: canonical];
    /// One source thread's audience policy (FIX 12559). Key: id16(source policy) + blake3 (32)
    /// of the source's thread key.
    SOURCE_AUDIENCE_THREAD: VaultMeta b"source_audience:thread:v1:" Named
        // Payload family: The source-audience policies, their events and the thread index stay
        // under the vault-wide seal until a per-owner compartment (row 17208).
        [restore: content] [family: unclassified] [tier: canonical];
}
