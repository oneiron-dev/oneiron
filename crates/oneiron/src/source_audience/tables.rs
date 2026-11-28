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
    /// Whether the floor backfill has raised archived rows too (FLOOR-BACKFILL-SKIPS-ARCHIVED-ROWS):
    /// set when a pass ends that began in a build that raises them with no row raised before its
    /// first page, and when the run again ends (#10265 Opus review P2-2). A vault that lost it
    /// runs the backfill again. Key: ().
    SOURCE_AUDIENCE_FLOOR_ARCHIVED_RAISED: VaultMeta b"source_audience:floor_archived_raised:v1:done" Named
        [restore: not_imaged] [family: not_imaged] [tier: derived];
    /// What a row whose floor waits waits on (READ-LINEAGE L1): each row or binding it waits to
    /// land here, so the write that lands it raises the waiting row again. Key: id16(awaited) +
    /// id16(waiting row).
    SOURCE_AUDIENCE_FLOOR_AWAITED: VaultMeta b"source_audience:floor_awaited:v1:" Named
        [restore: not_imaged] [family: not_imaged] [tier: derived];
    /// Whether the floor backfill has raised every row this vault held when it began
    /// (READ-LINEAGE L1). A vault that lost it runs the backfill again. Key: ().
    SOURCE_AUDIENCE_FLOOR_BACKFILL: VaultMeta b"source_audience:floor_backfill:v1:done" Named
        [restore: not_imaged] [family: not_imaged] [tier: derived];
    /// This vault's rows were all judged once (Fable design pass 31, section 5): `false` once the
    /// migration from the floor's wait marks has judged every row and empties the old tables,
    /// `true` once it has ended; either way no row is read as one written before floors. Key: ().
    SOURCE_AUDIENCE_FLOOR_MIGRATED: VaultMeta b"source_audience:floor_migrated:v1:done" Named
        // Restore class: Whether the migration ran stands with the rows the image holds, so a
        // restore never runs it again over rows it already judged.
        [restore: content] [family: structure] [tier: canonical];
    /// Each row this build has judged as the migration from the floor's wait marks judges it
    /// (Fable design pass 31, section 5; cases 64 to 66): its own marks, so a mark an older
    /// build left never counts as a visit. Value 0: judged in full; 1: an old fact a delete
    /// judged for one link before its tear, which the migration judges in full. Emptied when the
    /// migration ends; goes at the launch reset. Key: id16(row).
    SOURCE_AUDIENCE_FLOOR_MIGRATION_VISITED: VaultMeta b"source_audience:floor_migration_visited:v1:" Named
        // Restore class: Which rows were judged stands with the floors and open sets the image
        // holds, so a restore never judges a row twice.
        // Payload family: A row id and one byte: a marker with no payload of its own.
        [restore: content] [family: structure] [tier: canonical];
    /// Each input whose floor a row has not taken yet (Fable design pass 31): the row waits on
    /// it until it reads bound and whole here, and it reads sealed while the input reads erased.
    /// An entry leaves only when the row takes the input's floor. Key: id16(row) + id16(input).
    /// Value: the entry's flags (an old fact's entry, an attestation).
    SOURCE_AUDIENCE_FLOOR_OPEN: VaultMeta b"source_audience:floor_open:v1:" Named
        // Restore class: What a row still waits on stands with the rows the image holds: a
        // restore of an older set reads as the inputs say now, and the sweep takes each entry
        // whose input is bound and whole.
        // Payload family: Two row ids and a flag byte: markers with no payload of their own.
        [restore: content] [family: structure] [tier: canonical];
    /// The entries of SOURCE_AUDIENCE_FLOOR_OPEN by input (Fable design pass 31), so the write
    /// that makes an input bound finds the rows waiting on it. The sweep writes any missing pair
    /// again. Key: id16(input) + id16(row).
    SOURCE_AUDIENCE_FLOOR_OPEN_BY: VaultMeta b"source_audience:floor_open_by:v1:" Named
        [restore: not_imaged] [family: not_imaged] [tier: derived];
    /// A row whose floor waits (READ-LINEAGE L1): a row it was written from is not held here
    /// yet, a source's binding has not landed, its lineage does not resolve yet, or the floor
    /// of a row it was written from waits. Key: id16(row).
    SOURCE_AUDIENCE_FLOOR_PENDING: VaultMeta b"source_audience:floor_pending:v1:" Named
        [restore: not_imaged] [family: not_imaged] [tier: derived];
    /// A row whose floor was raised since the floor backfill began (READ-LINEAGE L1); the
    /// backfill clears them once it has raised every row. Key: id16(row).
    SOURCE_AUDIENCE_FLOOR_RAISED: VaultMeta b"source_audience:floor_raised:v1:" Named
        [restore: not_imaged] [family: not_imaged] [tier: derived];
    /// A row whose floor was raised since the floor backfill's run again began
    /// (FLOOR-BACKFILL-SKIPS-ARCHIVED-ROWS; #10265 review 2 P1-2): the run's own marks, so the
    /// marks a pass before it left never make it skip a row; cleared with them once it has raised
    /// every row. Key: id16(row).
    SOURCE_AUDIENCE_FLOOR_RAISED_AGAIN: VaultMeta b"source_audience:floor_raised_again:v1:" Named
        [restore: not_imaged] [family: not_imaged] [tier: derived];
    /// A redirect shell an owner's erase of its head scrubbed (SOURCE-STATE-L2 = A, the lead 21
    /// Nov 12:2x): a later owner erase of a shell, so an old fact that waits for good on it as an
    /// input deleted before floors reads sealed, whichever came first, the cascade or the
    /// migration's judgement of the fact. Goes at the launch reset. Key: id16(shell).
    SOURCE_AUDIENCE_FLOOR_SHELL_ERASED: VaultMeta b"source_audience:floor_shell_erased:v1:" Named
        // Restore class: An owner erase that reached a shell stands with the rows the image holds.
        // Payload family: A row id: a marker with no payload of its own.
        [restore: content] [family: structure] [tier: canonical];
    /// What a row whose floor waits waits on, by row (READ-LINEAGE L1; #10108 reviews): the
    /// marks of SOURCE_AUDIENCE_FLOOR_AWAITED, so a raise takes every mark the row no longer
    /// waits on. Key: id16(waiting row) + id16(awaited).
    SOURCE_AUDIENCE_FLOOR_WAITS: VaultMeta b"source_audience:floor_waits:v1:" Named
        [restore: not_imaged] [family: not_imaged] [tier: derived];
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
