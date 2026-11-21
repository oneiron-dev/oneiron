//! The owner's release of a calendar hold (CAL-OUTBOX-ROW-OF-REMOVED-SEAT-HOLDS-PULLS = C, the
//! lead 21 Nov 09:15; PLAN-CALENDAR-CONNECTOR-RELEASE-HOLD = A, 09:40).
//!
//! Only the writing seat moves or proves its outbox row, so a row of a seat that is killed, or
//! that no installed seat writes any more, holds the pulls of its EVENT that may be its write
//! coming back ([`super::cancelled_members_in_flight`], [`super::first_write_unsettled`],
//! [`super::unsettled_writes_of`]): no refund may be paid on a fault path. The hold stays until
//! the owner reconnects the seat (a same-config re-install writes the same scope and resumes the
//! row) or releases it here. A release is one mark per held row, in its own side table, as the
//! release read the row: a dead seat cannot reseal its outbox row, so the row stays as it is. A
//! row that moves after its release (a reconnected seat replays it) holds again.
//!
//! After a release the held pulls land, and a host cancel of the booking records the owner's
//! line "a cancel we can't attribute: refund by hand?" in place of the host-cancel refund
//! ([`released_hold_sequence`]). No release refunds by itself.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::super::door::installed_seat_scopes_in_txn;
use super::{
    CalendarWriteAction, CalendarWriteOutboxState, OUTBOX, OUTBOX_ROW_TAG, StoredOutboxRow,
};
use crate::calendar::connectors::door::{CalendarHoldRow, CalendarHoldSeat};
use crate::consent::AuthenticatedOwner;
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::memory::{MemoryError, MemoryResult};
use crate::side_table::{self, Named, SideTable};
use crate::vault::Vault;

/// The owner's release marks, by outbox id.
const RELEASES: SideTable<[u8; 32], ReleasedOutboxRow, Named> =
    SideTable::new(&side_table::CALENDAR_CONNECTOR_RELEASE);

/// One outbox row as the owner's release read it, and when the release landed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReleasedOutboxRow {
    instance: [u8; 16],
    updated_at: u64,
    released_at: u64,
}

/// Every release mark, read in one txn.
#[derive(Debug, Clone, Default)]
pub(super) struct OutboxReleases(BTreeMap<[u8; 32], ReleasedOutboxRow>);

impl OutboxReleases {
    /// Every release mark, read in `txn`.
    pub(super) fn read_in_txn(vault: &Vault, txn: &heed::RoTxn<'_>) -> crate::Result<Self> {
        Ok(Self(
            RELEASES.scan(&vault.store, txn)?.into_iter().collect(),
        ))
    }

    /// Whether the owner released `row` as it stands now: its mark names the row's carrier
    /// instance and last move.
    pub(super) fn released(&self, row: &StoredOutboxRow) -> bool {
        self.0.get(&row.outbox_id).is_some_and(|mark| {
            mark.instance == row.carrier.instance && mark.updated_at == row.updated_at
        })
    }
}

/// Whether `row` is an upsert that still holds pulls: prepared or remotely applied, or refused
/// with its stored copy's proof owed, as the pull holds read it.
fn holds_pulls(row: &StoredOutboxRow) -> bool {
    row.action == CalendarWriteAction::Upsert
        && match row.state {
            CalendarWriteOutboxState::Prepared | CalendarWriteOutboxState::RemoteApplied => true,
            CalendarWriteOutboxState::ReconcileRequired => row.stored_copy_unproven,
            CalendarWriteOutboxState::Committed => false,
        }
}

/// Whether `row` writes `event`: its EVENT, or a member it writes cancelled.
fn writes_event(row: &StoredOutboxRow, event: &EntityId) -> bool {
    row.event_ref == *event.as_bytes() || row.cancelled_members.contains(event.as_bytes())
}

/// One held row: the view the owner sees, and its key, carrier instance and last move.
struct HeldOutboxRow {
    outbox_id: [u8; 32],
    instance: [u8; 16],
    updated_at: u64,
    view: CalendarHoldRow,
}

/// Every outbox row that holds pulls of `event` while the seat that wrote it is out of service
/// and the owner has not released it, read in `txn`, in key order. A row whose writing seat is
/// installed and not killed is none: that seat settles or proves it. A killed seat names the
/// calendar from its setup; a removed one from the row's own strings, which a side-table write
/// may hold as custody handles.
fn held_rows_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    event: &EntityId,
) -> crate::Result<Vec<HeldOutboxRow>> {
    let releases = OutboxReleases::read_in_txn(vault, txn)?;
    let seats = installed_seat_scopes_in_txn(vault, txn)?;
    let mut held = Vec::new();
    for (_, row) in OUTBOX.scan_from(&vault.store, txn, OUTBOX_ROW_TAG)? {
        if !holds_pulls(&row) || !writes_event(&row, event) || releases.released(&row) {
            continue;
        }
        let (seat, system, calendar_ref) =
            match seats.iter().find(|seat| seat.scope == row.carrier.seat) {
                Some(seat) if !seat.killed => continue,
                Some(seat) => (
                    CalendarHoldSeat::Killed,
                    seat.system.clone(),
                    seat.calendar_ref.clone(),
                ),
                None => (
                    CalendarHoldSeat::Removed,
                    row.system.clone(),
                    row.calendar_ref.clone(),
                ),
            };
        held.push(HeldOutboxRow {
            outbox_id: row.outbox_id,
            instance: row.carrier.instance,
            updated_at: row.updated_at,
            view: CalendarHoldRow {
                system,
                calendar_ref,
                seat,
                sequence: row.sequence,
                outbox_id: bytes_to_hex_lower(&row.outbox_id),
                instance: bytes_to_hex_lower(&row.carrier.instance),
                updated_at: row.updated_at,
            },
        });
    }
    Ok(held)
}

/// The calendar holds of the booking `event`, read in `txn`, as the owner's card, inbox and
/// release sheet show them: one per outbox row that holds its pulls while the seat that wrote
/// it is out of service and the owner has not released it. Empty when nothing holds.
///
/// # Errors
///
/// Storage failures.
pub(crate) fn calendar_holds_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    event: &EntityId,
) -> crate::Result<Vec<CalendarHoldRow>> {
    Ok(held_rows_in_txn(vault, txn, event)?
        .into_iter()
        .map(|row| row.view)
        .collect())
}

/// Releases the calendar holds of `event` the owner's sheet showed (`shown`) under `owner`'s
/// proof, which the writer revalidates: one mark per held row as it stands, dated on the
/// vault's recording clock. `false`, writing nothing, when the holds read now are not exactly
/// those shown: a row moved, settled or was released since the preview.
///
/// It holds the vault's calendar admission turn, in which a pull reads the rows and a write
/// publishes and settles them, so neither lands between this check and the marks.
///
/// # Errors
///
/// A proof that no longer holds the vault's owner, a turn this thread already holds, and
/// storage failures.
pub(crate) fn release_calendar_holds_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    event: &EntityId,
    shown: &[CalendarHoldRow],
) -> MemoryResult<bool> {
    let _turn = crate::calendar::ingest::admission_turn(vault)
        .map_err(|error| MemoryError::bad_request(error.to_string()))?;
    let now = vault.now_recorded_at();
    let released = vault.with_write_txn_grouped(|wtxn| {
        owner.owner_authored_write_in_txn(vault, &*wtxn)?;
        let held = held_rows_in_txn(vault, &*wtxn, event)?;
        if held.is_empty() || !held.iter().map(|row| &row.view).eq(shown.iter()) {
            return Ok(false);
        }
        for row in &held {
            RELEASES.put(
                &vault.store,
                wtxn,
                &row.outbox_id,
                &ReleasedOutboxRow {
                    instance: row.instance,
                    updated_at: row.updated_at,
                    released_at: now,
                },
            )?;
        }
        Ok(true)
    })?;
    Ok(released)
}

/// The SEQUENCE a released hold of `event` staged, when the owner released one that still
/// stands as released: a host cancel of the booking then cannot be told from that write coming
/// back, so it records the owner's line "a cancel we can't attribute: refund by hand?" and
/// moves no money (CAL-OUTBOX-ROW-OF-REMOVED-SEAT-HOLDS-PULLS = C). `None` when none does.
///
/// # Errors
///
/// Storage failures.
pub(crate) fn released_hold_sequence(
    vault: &Vault,
    event: &EntityId,
) -> crate::Result<Option<u32>> {
    let txn = vault.store.env.read_txn()?;
    let releases = OutboxReleases::read_in_txn(vault, &txn)?;
    Ok(OUTBOX
        .scan_from(&vault.store, &txn, OUTBOX_ROW_TAG)?
        .into_iter()
        .map(|(_, row)| row)
        .find(|row| holds_pulls(row) && writes_event(row, event) && releases.released(row))
        .map(|row| row.sequence))
}
