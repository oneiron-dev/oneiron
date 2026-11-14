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
//! and no upsert of the UID is in flight; else it stays owed.

use super::super::door::CalendarConnectorOperation;
use super::super::remote::ics_content_hash;
use super::super::resource::read_blob_ref;
use super::super::seat::CalendarConnectorError;
use super::{
    CalendarWriteAction, CalendarWriteOutboxState, OUTBOX, OutboxKey, REMOTE_OBJECT,
    REMOTE_OBJECT_TAG, RemoteObjectKey, derive_outbox_id, open_cursor, remote_object_digest,
    remote_projection,
};
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
/// proves nothing.
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
    // Drop the table reader before any custody snapshot is acquired.
    let rows = {
        let txn = vault.store.env.read_txn().map_err(crate::Error::from)?;
        REMOTE_OBJECT.scan_from(&vault.store, &txn, REMOTE_OBJECT_TAG)?
    };
    let mut members = Vec::new();
    for (key, stored) in rows {
        if stored.carrier.seat != scope || stored.source_blob_ref.is_none() {
            continue;
        }
        let observation = CalendarRemoteObjectObservation(stored.carrier.instance);
        let mut row = remote_projection(stored);
        open_cursor(vault, operation, key.0, &mut row)?;
        let (Some(href), Some(source)) = (row.href, row.source_blob_ref.as_deref()) else {
            continue;
        };
        let read_observed = read_blob_ref(vault, source)?
            .and_then(|archived| ics_content_hash(&archived, &row.uid).ok())
            == Some(row.content_hash);
        members.push(CalendarCollectionMember {
            uid: row.uid,
            href,
            read_observed,
            observation,
        });
    }
    Ok(members)
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
    let outbox_id = derive_outbox_id(
        &scope,
        &seat.config.system,
        &seat.config.calendar_ref,
        uid,
        CalendarWriteAction::Upsert,
    );
    Ok(!OUTBOX
        .get(&vault.store, &txn, &OutboxKey(outbox_id))?
        .is_some_and(|row| {
            matches!(
                row.state,
                CalendarWriteOutboxState::Prepared | CalendarWriteOutboxState::RemoteApplied
            )
        }))
}
