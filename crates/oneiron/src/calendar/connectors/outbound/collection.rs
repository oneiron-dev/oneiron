//! A full listing's omissions, checked against this seat's remote object
//! rows (fix list row 19192).
//!
//! An empty-token `sync-collection` lists every member of a collection and
//! no removed one (RFC 6578 §3.4), so a resource this seat holds that such a
//! listing omits was removed. The wire reads the rows before it lists
//! ([`calendar_collection_members_for_operation`]), in one scan scoped to the
//! operation that opens each row's exact href once. An omission it reports
//! carries the row as it read it, and its admission
//! ([`omission_observed`]) lands only while the row is still that one
//! and no upsert of the UID is in flight; else it stays owed. A pulled
//! cancelled version of a member an upsert in flight on any seat of the
//! calendar writes cancelled ([`cancelled_members_in_flight`]) stays owed
//! the same way, and so does a pulled copy of a first write any seat has not
//! settled
//! ([`first_write_unsettled`]). A provider's report of a resource gone stays
//! held while an upsert of its UID on any seat of the calendar is unsettled
//! ([`unsettled_writes_of`]). A row the owner released while its writing seat
//! was out of service holds none of the others as long as it stands as
//! released ([`super::release`]; CAL-OUTBOX-ROW-OF-REMOVED-SEAT-HOLDS-PULLS);
//! a first write's copy stays held whatever the owner released, since it
//! would import a second EVENT.

use super::super::door::CalendarConnectorOperation;
use super::super::remote::ics_content_hash;
use super::super::resource::read_blob_ref;
use super::super::seat::CalendarConnectorError;
use super::release::OutboxReleases;
use super::{
    CalendarWriteAction, CalendarWriteOutboxState, LOCAL_UID_DOMAIN, OUTBOX, OUTBOX_ROW_TAG,
    OutboxKey, REMOTE_OBJECT, REMOTE_OBJECT_TAG, RemoteObjectKey, StoredWriteMarker,
    derive_outbox_id, local_uid, open_cursor, remote_object_digest, remote_projection,
};
use crate::calendar::passport::passport_uid_is;
use crate::code_run::CompareKnown;
use crate::entity_id::EntityId;
use crate::vault::Vault;

/// One remote object row of a seat as a full listing's snapshot read it.
/// Opaque: only the snapshot makes one, and only an omission's admission
/// compares it with the row that stands then.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CalendarRemoteObjectObservation([u8; 16]);

/// One resource of a seat's collection that a read has observed, as a full
/// listing's omission sweep needs it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CalendarCollectionMember {
    /// The VEVENT UID the row carries.
    pub uid: String,
    /// The exact resource path the row holds.
    pub href: String,
    /// Whether the row's content is the copy this seat last read and
    /// archived. `false` once a write settled content the archive does not
    /// hold (its resource may postdate the listing), so an omission of it is
    /// read back before it counts.
    pub read_observed: bool,
    /// The row as this snapshot read it.
    pub observation: CalendarRemoteObjectObservation,
}

/// Every resource of this authenticated installed seat that a read has
/// observed: each remote object row with an archived source, read before a
/// full listing so the listing's omissions can be reconciled.
///
/// A row only a write made (a local create no read has seen) is no member:
/// its resource may postdate the listing, so the listing's silence about it
/// proves nothing. It is one, unread, while a pull holds back a tombstone of
/// its UID that only a full listing's omission settles (`tombstone_held`):
/// the wire reads its resource back first, and only a gone answer makes the
/// omission (CAL-SEAT-DELETE-OF-WRITTEN-ONLY-EVENT-CANCELS-NOTHING).
///
/// # Errors
///
/// [`CalendarConnectorError::Calendar`] when the operation no longer stands,
/// a row's sealed values do not open for it, or the store fails.
pub fn calendar_collection_members_for_operation(
    vault: &Vault,
    operation: &CalendarConnectorOperation,
) -> Result<Vec<CalendarCollectionMember>, CalendarConnectorError> {
    operation.revalidate(vault)?;
    let scope = operation.literal_scope()?;
    let system = &operation.registration().seat.config.system;
    // Drop the table reader before any custody snapshot is acquired.
    let rows = {
        let txn = vault.store.env.read_txn().map_err(crate::Error::from)?;
        REMOTE_OBJECT.scan_from(&vault.store, &txn, REMOTE_OBJECT_TAG)?
    };
    let mut members = Vec::new();
    for (key, stored) in rows {
        if stored.carrier.seat != scope {
            continue;
        }
        let observation = CalendarRemoteObjectObservation(stored.carrier.instance);
        let mut row = remote_projection(stored);
        open_cursor(vault, operation, key.0, &mut row)?;
        let Some(href) = row.href else {
            continue;
        };
        let read_observed = match row.source_blob_ref.as_deref() {
            Some(source) => {
                read_blob_ref(vault, source)?
                    .and_then(|archived| ics_content_hash(&archived, &row.uid).ok())
                    == Some(row.content_hash)
            }
            None if tombstone_held(vault, system, &row.uid)? => false,
            None => continue,
        };
        members.push(CalendarCollectionMember {
            uid: row.uid,
            href,
            read_observed,
            observation,
        });
    }
    Ok(members)
}

/// Whether a live passport of `system` for `uid` holds a removal report a
/// pull held back unread (`deferred_cancel_seen_at`), which a full listing's
/// omission of the resource settles as the tombstone it was.
fn tombstone_held(vault: &Vault, system: &str, uid: &str) -> Result<bool, CalendarConnectorError> {
    let Some(event) = crate::calendar::passport::resolve_event_by_uid(vault, uid)? else {
        return Ok(false);
    };
    Ok(
        crate::calendar::passport::live_passport_for(vault, &event, system, uid)?
            .is_some_and(|(_, passport)| passport.deferred_cancel_seen_at.is_some()),
    )
}

/// What the outbox rows of every seat of the vault hold of upserts of `uid`
/// under `system`, which a provider's report of the resource gone may be
/// coming back from. Seats of one calendar share its system and its
/// passports, but not their outboxes: a seat's cadence is part of its outbox
/// scope (`CalendarConnectorOperation::literal_scope`), so another seat of
/// the calendar may hold the write
/// (CAL-SEAT-DELETE-OF-WRITTEN-ONLY-EVENT-CANCELS-NOTHING).
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct UnsettledWrites {
    /// An upsert that writes a member cancelled is prepared or remotely
    /// applied: its settlement has not marked the member's passport yet.
    pub(crate) cancelled_in_flight: bool,
    /// A replayed upsert's precondition refusal read no copy
    /// ([`super::CalendarWriteOutboxRow::stored_copy_unproven`]): the
    /// provider may hold the write's own copy, or have deleted it as a
    /// provider that keeps a cancelled event as a deleted one does.
    pub(crate) copy_unproven: bool,
}

/// [`UnsettledWrites`] of `uid` under the pulling seat's system, read
/// across every seat's outbox rows without opening their sealed values. A
/// row is one of them when its readable strings name them or its key is the
/// one its writing seat derives for them on the pulling seat's calendar
/// (`upsert_row_of`): a side-table write may hold a string as a custody
/// handle (CAL-OUTBOX-SCAN-MASKED-SYSTEM-MISSES-ROW).
///
/// The caller holds the vault's calendar admission turn, in which a write
/// publishes its prepared row and settles, so neither lands between this
/// read and the admission it guards.
///
/// # Errors
///
/// Storage failures.
pub(crate) fn unsettled_writes_of(
    vault: &Vault,
    operation: &CalendarConnectorOperation,
    uid: &str,
) -> Result<UnsettledWrites, CalendarConnectorError> {
    let seat = &operation.registration().seat;
    let system = seat.config.system.as_str();
    let calendar_ref = seat.config.calendar_ref.as_str();
    let (rows, releases) = {
        let txn = vault.store.env.read_txn().map_err(crate::Error::from)?;
        (
            OUTBOX.scan_from(&vault.store, &txn, OUTBOX_ROW_TAG)?,
            OutboxReleases::read_in_txn(vault, &txn)?,
        )
    };
    let mut writes = UnsettledWrites::default();
    for (_, row) in rows {
        if !upsert_row_of(&row, system, calendar_ref, uid) || releases.released(&row)? {
            continue;
        }
        match row.state {
            CalendarWriteOutboxState::Prepared | CalendarWriteOutboxState::RemoteApplied => {
                writes.cancelled_in_flight |= !row.cancelled_members.is_empty();
            }
            CalendarWriteOutboxState::ReconcileRequired => {
                writes.copy_unproven |= row.stored_copy_unproven;
            }
            CalendarWriteOutboxState::Committed => {}
        }
    }
    Ok(writes)
}

/// Whether the omission of `uid` a full listing reported may land now: this
/// seat's remote object row is still the one `observation` read and no
/// upsert of `uid` is prepared or remotely applied. `false` leaves the
/// omission owed: the sync applies every other change and the next pull
/// lists the calendar whole again, so it is read again, never dropped.
///
/// The caller holds the vault's calendar admission turn, in which a write
/// publishes its prepared row too, so no write begins between this check and
/// the absence it admits.
///
/// # Errors
///
/// Scope and storage failures.
pub(crate) fn omission_observed(
    vault: &Vault,
    operation: &CalendarConnectorOperation,
    uid: &str,
    observation: CalendarRemoteObjectObservation,
) -> Result<bool, CalendarConnectorError> {
    let seat = &operation.registration().seat;
    let scope = operation.literal_scope()?;
    let txn = vault.store.env.read_txn().map_err(crate::Error::from)?;
    let key = remote_object_digest(&scope, &seat.config.system, &seat.config.calendar_ref, uid);
    if REMOTE_OBJECT
        .get(&vault.store, &txn, &RemoteObjectKey(key))?
        .is_none_or(|row| row.carrier.instance != observation.0)
    {
        return Ok(false);
    }
    Ok(upsert_in_flight(vault, &txn, &scope, operation, uid)?.is_none())
}

/// The members an upsert of `uid` still in flight on any seat of the vault
/// (prepared or remotely applied, not yet settled, or refused with its
/// stored copy's proof owed:
/// [`super::CalendarWriteOutboxRow::stored_copy_unproven`]) writes
/// cancelled, each with the RECURRENCE-ID its staged VEVENT carries under
/// `uid` ([`super::staged_recurrence_id`]); empty when none is in flight. A
/// pulled cancelled version of such a member may be that write coming back
/// before its settlement marks the member's passport `written_cancelled`,
/// and would read as a host cancel that moves deposit money, so the pull
/// leaves the resource owed and reads it again once the write settles
/// (BK-DEPOSIT-REWRITTEN-ECHO-OF-OWNER-WRITE-REFUNDS). The pull matches its
/// VEVENTs to them by that identity, whatever exception claims a member
/// holds now; a first write's copy is held back before, whole
/// ([`first_write_unsettled`]).
///
/// Seats of one calendar share its system and its passports but not their
/// outboxes ([`UnsettledWrites`]), so the pulling seat reads every seat's
/// rows (CAL-SECOND-SEAT-CANCELLED-VERSION-MISSES-OTHER-SEAT-WRITE). Its own
/// write in flight holds any cancelled version, as before: its own write
/// call settles it or refuses it. Only the writing seat moves or proves a
/// row, and its owner may stop it with the row unsettled, so any other row,
/// and a refused replay's even on its own seat (no pull proves a copy
/// below its write), holds only a copy that may be its write's own
/// (`stored_copy_of`): no VEVENT, `lowest_sequence` the lowest
/// SEQUENCE among them, below the staged SEQUENCE, which a provider storing
/// the write keeps or raises; and no write marker other than the staged one,
/// which the write keeps on every call. Any other copy is another writer's,
/// may be the host's own cancel, and must land (reviews of #10020). A copy
/// with no marker, from a provider or client that drops unknown properties,
/// stays held.
///
/// A row is one of `uid` under the pulling seat's system when its readable
/// strings name them, or when its key is the one its writing seat's scope
/// derives for them on the pulling seat's calendar: a side-table write may
/// hold a string as a custody handle, but the key is derived from the
/// literal names, as the pulling seat finds its own row
/// (`upsert_in_flight`).
///
/// The read scans every seat's outbox rows, so the pull asks it only for a
/// copy that carries a cancelled VEVENT; `ics` is that copy. It opens no
/// row's sealed values.
///
/// The caller holds the vault's calendar admission turn, in which a write
/// publishes its prepared row and settles, so neither lands between this
/// read and the admission it guards.
///
/// # Errors
///
/// Scope and storage failures, and a stored member that is no entity id.
pub(crate) fn cancelled_members_in_flight(
    vault: &Vault,
    operation: &CalendarConnectorOperation,
    uid: &str,
    ics: &[u8],
    lowest_sequence: u32,
) -> Result<Vec<(EntityId, Option<u64>)>, CalendarConnectorError> {
    let seat = &operation.registration().seat;
    let system = seat.config.system.as_str();
    let calendar_ref = seat.config.calendar_ref.as_str();
    let own_row = derive_outbox_id(
        &operation.literal_scope()?,
        system,
        calendar_ref,
        uid,
        CalendarWriteAction::Upsert,
    );
    let copy_marker = super::stored_write_marker(ics, uid);
    // Drop the table reader before a row staged without its RECURRENCE-IDs
    // reads its members' claims.
    let (rows, releases) = {
        let txn = vault.store.env.read_txn().map_err(crate::Error::from)?;
        (
            OUTBOX.scan_from(&vault.store, &txn, OUTBOX_ROW_TAG)?,
            OutboxReleases::read_in_txn(vault, &txn)?,
        )
    };
    let mut members = Vec::new();
    for (_, stored) in rows {
        if releases.released(&stored)? {
            continue;
        }
        let may_be_own = lowest_sequence >= stored.sequence
            && match (stored.write_marker, &copy_marker) {
                (Some(staged), StoredWriteMarker::One(marker)) => *marker == staged,
                (Some(_), StoredWriteMarker::Conflicting) => false,
                _ => true,
            };
        let in_flight = match stored.state {
            CalendarWriteOutboxState::Prepared | CalendarWriteOutboxState::RemoteApplied => {
                may_be_own || stored.outbox_id == own_row
            }
            CalendarWriteOutboxState::ReconcileRequired => {
                stored.stored_copy_unproven && may_be_own
            }
            CalendarWriteOutboxState::Committed => false,
        };
        if !in_flight
            || stored.cancelled_members.is_empty()
            || !upsert_row_of(&stored, system, calendar_ref, uid)
        {
            continue;
        }
        let row = stored.into_row()?;
        for &member in &row.cancelled_members {
            members.push((member, super::staged_recurrence_id(vault, &row, member)?));
        }
    }
    Ok(members)
}

/// Whether `stored` is an upsert row of `uid` under `system`: its readable
/// strings name them, or its key is the one its writing seat's scope (its
/// carrier's seat digest) derives for them on `calendar_ref`.
fn upsert_row_of(
    stored: &super::StoredOutboxRow,
    system: &str,
    calendar_ref: &str,
    uid: &str,
) -> bool {
    stored.action == CalendarWriteAction::Upsert
        && ((stored.system == system && stored.uid == uid)
            || stored.outbox_id
                == derive_outbox_id(
                    &stored.carrier.seat,
                    system,
                    calendar_ref,
                    uid,
                    CalendarWriteAction::Upsert,
                ))
}

/// Whether a first write of `uid` on any seat of the vault has not bound
/// the UID yet: prepared or remotely applied, or refused with its stored
/// copy's proof owed ([`super::CalendarWriteOutboxRow::stored_copy_unproven`]).
/// A first write stages under the UID it minted for its EVENT
/// ([`super::is_first_write`]), and no passport names that UID before the
/// write binds it, so a pulled resource of `uid` may be that write coming
/// back, and would import a second EVENT. Another seat may read the same
/// collection under another system name, and its outbox holds no row of
/// the write, so the check reads every seat's rows. The pull leaves the
/// resource owed and reads it again once the write settles, or its writing
/// seat's pull proves the copy
/// (CAL-FIRST-WRITE-COPY-PULLED-UNSETTLED-IMPORTS-DUPLICATE-EVENT).
///
/// A row stages under `uid` when its readable UID is `uid`, or its key is
/// the one its writing seat derives for `uid` under its readable system and
/// calendar, or under the pulling seat's, or its readable UID is `uid` as
/// custody reads it ([`passport_uid_is`]): a side-table write may hold a
/// string as a custody handle, the system name of a seat the pulling one
/// does not share too (CAL-OUTBOX-SCAN-MASKED-SYSTEM-MISSES-ROW, blind
/// review round 1 of #10090).
///
/// Only a UID of the minted form that resolves to no EVENT reads the
/// outbox, and the check opens no row's sealed values. The values custody
/// holds are read only for a row of the EVENT whose UID `uid` is that the
/// other matches miss.
///
/// The caller holds the vault's calendar admission turn, in which a write
/// publishes its prepared row and settles, so neither lands between this
/// read and the admission it guards.
///
/// # Errors
///
/// Resolution and storage failures, and a stored row that does not decode.
pub(crate) fn first_write_unsettled(
    vault: &Vault,
    operation: &CalendarConnectorOperation,
    uid: &str,
) -> Result<bool, CalendarConnectorError> {
    // Only a first write mints a UID of the form `<event>@calendar.invalid`
    // ([`local_uid`]); one that resolves to an EVENT is bound already.
    let minted_form = uid
        .strip_suffix(LOCAL_UID_DOMAIN)
        .and_then(|event| event.strip_suffix('@'))
        .is_some();
    if !minted_form || crate::calendar::passport::resolve_event_by_uid(vault, uid)?.is_some() {
        return Ok(false);
    }
    let seat = &operation.registration().seat;
    let system = seat.config.system.as_str();
    let calendar_ref = seat.config.calendar_ref.as_str();
    // An owner's release of a held row never lifts this check: the copy would
    // still import a second EVENT, so only the writing seat's settlement or
    // proof binds the UID (`super::release`).
    let rows = {
        let txn = vault.store.env.read_txn().map_err(crate::Error::from)?;
        OUTBOX.scan_from(&vault.store, &txn, OUTBOX_ROW_TAG)?
    };
    let base_known = || vault.known_values_now();
    let known = CompareKnown::new(Some(&base_known));
    for (_, row) in rows {
        let unsettled = match row.state {
            CalendarWriteOutboxState::Prepared | CalendarWriteOutboxState::RemoteApplied => true,
            CalendarWriteOutboxState::ReconcileRequired => row.stored_copy_unproven,
            CalendarWriteOutboxState::Committed => false,
        };
        if !unsettled
            || row.action != CalendarWriteAction::Upsert
            || !EntityId::from_bytes(row.event_ref).is_ok_and(|event| local_uid(&event) == uid)
        {
            continue;
        }
        if row.uid == uid
            || row.outbox_id
                == derive_outbox_id(
                    &row.carrier.seat,
                    &row.system,
                    &row.calendar_ref,
                    uid,
                    CalendarWriteAction::Upsert,
                )
            || upsert_row_of(&row, system, calendar_ref, uid)
            || passport_uid_is(&row.uid, uid, &known)?
        {
            return Ok(true);
        }
    }
    Ok(false)
}

/// This seat's outbox row of a replayed upsert of `uid` whose precondition
/// refusal's read proved its stored copy neither its own nor another
/// writer's, so the seat's next pull of the resource proves it
/// (BK-ECHO-RECONCILE-FAILURE-RELEASES-UNMARKED-COPY), with the row's
/// revision as stored ([`super::release::revision`]). Its sealed values are
/// not opened.
///
/// # Errors
///
/// Scope and storage failures, and a stored row that does not decode.
pub(super) fn unproven_replay(
    vault: &Vault,
    operation: &CalendarConnectorOperation,
    uid: &str,
) -> Result<Option<(super::CalendarWriteOutboxRow, [u8; 32])>, CalendarConnectorError> {
    let seat = &operation.registration().seat;
    let scope = operation.literal_scope()?;
    let outbox_id = derive_outbox_id(
        &scope,
        &seat.config.system,
        &seat.config.calendar_ref,
        uid,
        CalendarWriteAction::Upsert,
    );
    // Drop the table reader before the caller opens the row's custody.
    let stored = {
        let txn = vault.store.env.read_txn().map_err(crate::Error::from)?;
        OUTBOX.get(&vault.store, &txn, &OutboxKey(outbox_id))?
    };
    let Some(stored) = stored.filter(|row| {
        row.state == CalendarWriteOutboxState::ReconcileRequired && row.stored_copy_unproven
    }) else {
        return Ok(None);
    };
    let revision = super::release::revision(&stored)?;
    Ok(Some((stored.into_row()?, revision)))
}

/// The outbox row, on any seat that writes `uid` under this seat's system
/// ([`upsert_row_of`]), of a refused upsert whose proof is no longer owed
/// (its refusal's read, or a later pull, read another writer's copy:
/// [`unproven_replay`] no longer finds it) while the pulled copy `ics`
/// carries that write's own marker.
/// The marker is fresh for each staged write, so the copy is that write
/// stored by a call sent before the refusal, whose answer was lost, after
/// the read that proved the row: an overlapping replay holds the row's
/// precondition too, and the provider's ETag may recur
/// (CAL-REFUSED-WRITE-LATE-SEND-LANDS-UNFENCED). A released row is not read
/// ([`OutboxReleases`]). With the row's revision as stored
/// ([`super::release::revision`]) and its names set to this seat's literal
/// ones, which its key or readable strings show it stands for. Its sealed
/// values are not opened.
///
/// # Errors
///
/// Storage failures, and a stored row that does not decode.
pub(super) fn proven_refused_write_of_copy(
    vault: &Vault,
    operation: &CalendarConnectorOperation,
    uid: &str,
    ics: &[u8],
) -> Result<Option<(super::CalendarWriteOutboxRow, [u8; 32])>, CalendarConnectorError> {
    let StoredWriteMarker::One(marker) = super::stored_write_marker(ics, uid) else {
        return Ok(None);
    };
    let seat = &operation.registration().seat;
    let system = seat.config.system.as_str();
    let calendar_ref = seat.config.calendar_ref.as_str();
    let (rows, releases) = {
        let txn = vault.store.env.read_txn().map_err(crate::Error::from)?;
        (
            OUTBOX.scan_from(&vault.store, &txn, OUTBOX_ROW_TAG)?,
            OutboxReleases::read_in_txn(vault, &txn)?,
        )
    };
    for (_, stored) in rows {
        if stored.state != CalendarWriteOutboxState::ReconcileRequired
            || stored.stored_copy_unproven
            || stored.write_marker != Some(marker)
            || !upsert_row_of(&stored, system, calendar_ref, uid)
            || releases.released(&stored)?
        {
            continue;
        }
        let revision = super::release::revision(&stored)?;
        let mut row = stored.into_row()?;
        row.system = system.to_owned();
        row.calendar_ref = calendar_ref.to_owned();
        row.uid = uid.to_owned();
        return Ok(Some((row, revision)));
    }
    Ok(None)
}

/// This seat's outbox rows that owed the proof of a refused write's stored
/// copy ([`unproven_replay`]) when a pull began, read before the pull's
/// provider read: each row's key and revision as stored
/// ([`super::release::revision`]). Opaque: only
/// [`unproven_replays_before_read`] makes one, and only the proof of a pulled
/// copy compares a row with it.
#[derive(Debug, Clone, Default)]
pub(crate) struct UnprovenReplaysBeforeRead(Vec<([u8; 32], [u8; 32])>);

impl UnprovenReplaysBeforeRead {
    /// Whether the row `outbox_id` owed its proof before the pull's read
    /// began and has not moved since: it stands at the `revision` read then,
    /// so its refusal, and the failed read that refusal made, came before
    /// that read. A row's carrier instance and time can repeat across its
    /// moves on one clock reading; its revision cannot (blind review round 1
    /// of #10130).
    pub(super) fn holds(&self, outbox_id: &[u8; 32], revision: &[u8; 32]) -> bool {
        self.0.contains(&(*outbox_id, *revision))
    }
}

/// Every outbox row of this seat's literal scope that owes the proof of its
/// stored copy, as [`UnprovenReplaysBeforeRead`]. Its sealed values are not
/// opened. A pull reads it before its provider read, outside the admission
/// turn; the proof reads its row again under the turn and counts this read
/// only for the row it read here (CAL-OUTBOX-ROW-OF-REMOVED-SEAT-HOLDS-PULLS).
///
/// # Errors
///
/// Scope and storage failures.
pub(crate) fn unproven_replays_before_read(
    vault: &Vault,
    operation: &CalendarConnectorOperation,
) -> Result<UnprovenReplaysBeforeRead, CalendarConnectorError> {
    let scope = operation.literal_scope()?;
    let rows = {
        let txn = vault.store.env.read_txn().map_err(crate::Error::from)?;
        OUTBOX.scan_from(&vault.store, &txn, OUTBOX_ROW_TAG)?
    };
    let mut owed = Vec::new();
    for (_, row) in rows {
        if row.carrier.seat == scope
            && row.state == CalendarWriteOutboxState::ReconcileRequired
            && row.stored_copy_unproven
        {
            owed.push((row.outbox_id, super::release::revision(&row)?));
        }
    }
    Ok(UnprovenReplaysBeforeRead(owed))
}

/// This seat's outbox row of an upsert of `uid` while it is prepared or
/// remotely applied: staged, and its passports not yet settled.
fn upsert_in_flight(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    scope: &[u8; 32],
    operation: &CalendarConnectorOperation,
    uid: &str,
) -> Result<Option<super::StoredOutboxRow>, CalendarConnectorError> {
    let seat = &operation.registration().seat;
    let outbox_id = derive_outbox_id(
        scope,
        &seat.config.system,
        &seat.config.calendar_ref,
        uid,
        CalendarWriteAction::Upsert,
    );
    let Some(row) = OUTBOX.get(&vault.store, txn, &OutboxKey(outbox_id))? else {
        return Ok(None);
    };
    let in_flight = matches!(
        row.state,
        CalendarWriteOutboxState::Prepared | CalendarWriteOutboxState::RemoteApplied
    ) && !OutboxReleases::read_in_txn(vault, txn)?.released(&row)?;
    Ok(in_flight.then_some(row))
}
