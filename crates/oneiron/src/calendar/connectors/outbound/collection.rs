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
//! cancelled version of a member an upsert in flight writes cancelled
//! ([`cancelled_members_in_flight`]) stays owed the same way, and so does a
//! pulled copy of a first write any seat has not settled
//! ([`first_write_unsettled`]). A provider's report of a resource gone stays
//! held while an upsert of its UID on any seat of the calendar is unsettled
//! ([`unsettled_writes_of`]).

use super::super::door::CalendarConnectorOperation;
use super::super::remote::ics_content_hash;
use super::super::resource::read_blob_ref;
use super::super::seat::CalendarConnectorError;
use super::{
    CalendarWriteAction, CalendarWriteOutboxState, LOCAL_UID_DOMAIN, OUTBOX, OUTBOX_ROW_TAG,
    OutboxKey, REMOTE_OBJECT, REMOTE_OBJECT_TAG, RemoteObjectKey, derive_outbox_id, local_uid,
    open_cursor, remote_object_digest, remote_projection,
};
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

/// [`UnsettledWrites`] of `uid` under `system`, read across every seat's
/// outbox rows without opening their sealed values.
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
    system: &str,
    uid: &str,
) -> Result<UnsettledWrites, CalendarConnectorError> {
    let rows = {
        let txn = vault.store.env.read_txn().map_err(crate::Error::from)?;
        OUTBOX.scan_from(&vault.store, &txn, OUTBOX_ROW_TAG)?
    };
    let mut writes = UnsettledWrites::default();
    for (_, row) in rows {
        if row.action != CalendarWriteAction::Upsert || row.system != system || row.uid != uid {
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

/// The members an upsert of `uid` still in flight (prepared or remotely
/// applied, not yet settled) writes cancelled, each with the RECURRENCE-ID
/// its staged VEVENT carries under `uid` ([`super::staged_recurrence_id`]);
/// empty when none is in flight. A pulled cancelled version of such a member
/// may be that write coming back before its settlement marks the member's
/// passport `written_cancelled`, and would read as a host cancel that moves
/// deposit money, so the pull leaves the resource owed and reads it again
/// once the write settles (BK-DEPOSIT-REWRITTEN-ECHO-OF-OWNER-WRITE-REFUNDS).
/// The pull matches its VEVENTs to them by that identity, whatever
/// exception claims a member holds now; a first write's copy is held back
/// before, whole ([`first_write_unsettled`]).
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
) -> Result<Vec<(EntityId, Option<u64>)>, CalendarConnectorError> {
    let scope = operation.literal_scope()?;
    // Drop the table reader before a row staged without its RECURRENCE-IDs
    // reads its members' claims.
    let stored = {
        let txn = vault.store.env.read_txn().map_err(crate::Error::from)?;
        upsert_in_flight(vault, &txn, &scope, operation, uid)?
    };
    let Some(row) = stored else {
        return Ok(Vec::new());
    };
    let row = row.into_row()?;
    row.cancelled_members
        .iter()
        .map(|&member| Ok((member, super::staged_recurrence_id(vault, &row, member)?)))
        .collect()
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
/// Only a UID of the minted form that resolves to no EVENT reads the
/// outbox, and the check opens no row's sealed values.
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
    let rows = {
        let txn = vault.store.env.read_txn().map_err(crate::Error::from)?;
        OUTBOX.scan_from(&vault.store, &txn, OUTBOX_ROW_TAG)?
    };
    Ok(rows.into_iter().any(|(_, row)| {
        let unsettled = match row.state {
            CalendarWriteOutboxState::Prepared | CalendarWriteOutboxState::RemoteApplied => true,
            CalendarWriteOutboxState::ReconcileRequired => row.stored_copy_unproven,
            CalendarWriteOutboxState::Committed => false,
        };
        unsettled
            && row.action == CalendarWriteAction::Upsert
            && row.uid == uid
            && EntityId::from_bytes(row.event_ref).is_ok_and(|event| local_uid(&event) == uid)
    }))
}

/// This seat's outbox row of a replayed upsert of `uid` whose precondition
/// refusal's read proved its stored copy neither its own nor another
/// writer's, so the seat's next pull of the resource proves it
/// (BK-ECHO-RECONCILE-FAILURE-RELEASES-UNMARKED-COPY). Its sealed values are
/// not opened.
///
/// # Errors
///
/// Scope and storage failures, and a stored row that does not decode.
pub(super) fn unproven_replay(
    vault: &Vault,
    operation: &CalendarConnectorOperation,
    uid: &str,
) -> Result<Option<super::CalendarWriteOutboxRow>, CalendarConnectorError> {
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
    stored
        .filter(|row| {
            row.state == CalendarWriteOutboxState::ReconcileRequired && row.stored_copy_unproven
        })
        .map(super::StoredOutboxRow::into_row)
        .transpose()
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
    Ok(OUTBOX
        .get(&vault.store, txn, &OutboxKey(outbox_id))?
        .filter(|row| {
            matches!(
                row.state,
                CalendarWriteOutboxState::Prepared | CalendarWriteOutboxState::RemoteApplied
            )
        }))
}
