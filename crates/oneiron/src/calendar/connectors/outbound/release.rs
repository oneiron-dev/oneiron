//! The owner's release of a calendar hold (CAL-OUTBOX-ROW-OF-REMOVED-SEAT-HOLDS-PULLS = C, the
//! lead 21 Nov 09:15; PLAN-CALENDAR-CONNECTOR-RELEASE-HOLD = A, 09:40).
//!
//! Only the writing seat moves or proves its outbox row, so a row of a seat that is killed, or
//! that no installed seat writes any more, holds the pulls of its EVENT that may be its write
//! coming back ([`super::cancelled_members_in_flight`], [`super::first_write_unsettled`],
//! [`super::unsettled_writes_of`]): no refund may be paid on a fault path. The hold stays until
//! the owner reconnects the seat (a same-config re-install writes the same scope and resumes the
//! row) or releases it here. A release is one mark per held row, in its own side table, naming
//! the row's revision as the release read it (a digest of the whole stored row): a dead seat
//! cannot reseal its outbox row, so the row stays as it is. A mark counts only while the row
//! stands at that revision and no installed seat in service writes its scope: a row that moves
//! after its release, or whose seat the owner reconnects, holds again.
//!
//! A first write's row is not released: its copy names a UID no passport binds yet, and would
//! import a second EVENT ([`super::first_write_unsettled`] holds it whatever the owner
//! released), so only reconnecting its seat lifts that hold. A later write of the EVENT keeps
//! the UID the first one minted; once a passport carries that UID, its row is released like any
//! other.
//!
//! After a release the held pulls land, and a host cancel of the booking records the owner's
//! line "a cancel we can't attribute: refund by hand?" in place of the host-cancel refund
//! ([`record_released_hold_cancel`]). No release refunds by itself.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use super::super::door::{InstalledSeatScope, installed_seat_scopes_in_txn};
use super::super::replay_evidence::record_replay_cancel_evidence_in_txn;
use super::super::seat::CalendarConnectorError;
use super::{
    CalendarWriteAction, CalendarWriteOutboxState, OUTBOX, OUTBOX_ROW_TAG, StoredOutboxRow,
    derive_outbox_id, local_uid,
};
use crate::calendar::CalendarError;
use crate::calendar::claims::{PREDICATE_CALENDAR_PASSPORT, decode_passport_value};
use crate::calendar::connectors::door::{CalendarHoldRow, CalendarHoldSeat};
use crate::claim::{ClaimLifecycleStatus, ClaimSubject};
use crate::consent::AuthenticatedOwner;
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::memory::{MemoryError, MemoryResult};
use crate::side_table::{self, Named, SideTable};
use crate::vault::Vault;

/// The owner's release marks, by outbox id.
const RELEASES: SideTable<[u8; 32], ReleasedOutboxRow, Named> =
    SideTable::new(&side_table::CALENDAR_CONNECTOR_RELEASE);

/// One outbox row as the owner's release read it (its revision), and when the release landed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReleasedOutboxRow {
    revision: [u8; 32],
    released_at: u64,
}

/// The revision of `row`: the digest of the whole row as stored. Any move of the row changes a
/// field of it (its state, receipt, proof flag, SEQUENCE or time), whatever clock reading the
/// move carries, and every write seals its carrier again, so a release of one revision never
/// covers the row after it moves.
pub(super) fn revision(row: &StoredOutboxRow) -> crate::Result<[u8; 32]> {
    super::super::literal::digest(row)
}

/// The outbox scopes that an installed seat in service (not killed) writes. Such a seat settles
/// or proves its rows itself, so none of them is held, and no release of one counts.
fn scopes_in_service(seats: &[InstalledSeatScope]) -> BTreeSet<[u8; 32]> {
    seats
        .iter()
        .filter(|seat| !seat.killed)
        .map(|seat| seat.scope)
        .collect()
}

/// Every release mark, with the outbox scopes in service, read in one txn.
#[derive(Debug, Clone, Default)]
pub(super) struct OutboxReleases {
    marks: BTreeMap<[u8; 32], ReleasedOutboxRow>,
    in_service: BTreeSet<[u8; 32]>,
}

impl OutboxReleases {
    /// Every release mark, read in `txn`; the installed seats are read only when a mark exists.
    pub(super) fn read_in_txn(vault: &Vault, txn: &heed::RoTxn<'_>) -> crate::Result<Self> {
        let marks: BTreeMap<_, _> = RELEASES.scan(&vault.store, txn)?.into_iter().collect();
        let in_service = if marks.is_empty() {
            BTreeSet::new()
        } else {
            scopes_in_service(&installed_seat_scopes_in_txn(vault, txn)?)
        };
        Ok(Self { marks, in_service })
    }

    /// Whether the owner released `row` as it stands now while its writing seat is still out of
    /// service: its mark names the row's revision, and no installed seat in service writes its
    /// scope.
    ///
    /// # Errors
    ///
    /// A row that does not encode.
    pub(super) fn released(&self, row: &StoredOutboxRow) -> crate::Result<bool> {
        let Some(mark) = self.marks.get(&row.outbox_id) else {
            return Ok(false);
        };
        if self.in_service.contains(&row.carrier.seat) {
            return Ok(false);
        }
        Ok(mark.revision == revision(row)?)
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

/// Whether `row` writes `event`: its EVENT, a member of its resource (the pull holds read the
/// resource of the row's UID whole), or a member it writes cancelled.
fn writes_event(row: &StoredOutboxRow, event: &EntityId) -> bool {
    let event = event.as_bytes();
    row.event_ref == *event
        || row
            .component_hashes
            .iter()
            .any(|(member, _)| member == event)
        || row.cancelled_members.contains(event)
}

/// Whether `row` stages the first write of its EVENT, read in `txn`: under the UID the write
/// minted for it ([`local_uid`]), by its readable UID or by its key under its own names (a
/// side-table write may hold the UID as a custody handle; the key derives from the literal),
/// while no live passport on the EVENT carries that UID. No passport binds that UID until the
/// write settles or its seat proves the copy, so a pulled copy of it would import a second
/// EVENT, and [`super::first_write_unsettled`] holds it whatever the owner released. Such a row
/// is not released. A later write of the EVENT stages under the same UID, which a passport
/// then carries, so its row is released like any other (blind review round 1 of #10130).
///
/// # Errors
///
/// Store failures, and a passport claim that does not decode.
fn stages_first_write(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    row: &StoredOutboxRow,
) -> crate::Result<bool> {
    let Ok(event) = EntityId::from_bytes(row.event_ref) else {
        return Ok(false);
    };
    let uid = local_uid(&event);
    let minted = row.action == CalendarWriteAction::Upsert
        && (row.uid == uid
            || row.outbox_id
                == derive_outbox_id(
                    &row.carrier.seat,
                    &row.system,
                    &row.calendar_ref,
                    &uid,
                    CalendarWriteAction::Upsert,
                ));
    Ok(minted && !uid_carried_in_txn(vault, txn, &event, &uid)?)
}

/// Whether a lifecycle-active passport on `event`, pending or not, carries `uid` as written,
/// read in `txn`: the passport a settled write, or its seat's proof of the copy, files under
/// the UID the write minted.
///
/// # Errors
///
/// Store failures, and a passport claim that does not decode.
fn uid_carried_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    event: &EntityId,
    uid: &str,
) -> crate::Result<bool> {
    for id in vault.claims_for_subject_in_txn(txn, event)? {
        let Some(body) = vault.get_claim_in_txn(txn, &id)? else {
            continue;
        };
        if body.predicate == PREDICATE_CALENDAR_PASSPORT
            && body.subject == ClaimSubject::Entity(*event)
            && body.lifecycle == ClaimLifecycleStatus::Active
            && decode_passport_value(&body.value)?.uid == uid
        {
            return Ok(true);
        }
    }
    Ok(false)
}

/// One held row: the view the owner sees, and its key and revision.
struct HeldOutboxRow {
    outbox_id: [u8; 32],
    revision: [u8; 32],
    view: CalendarHoldRow,
}

/// Every outbox row that holds pulls of `event` while the seat that wrote it is out of service
/// and the owner has not released it, read in `txn`, in key order. A row whose scope an
/// installed seat in service writes is none: that seat settles or proves it, whatever other
/// seat of the scope is killed (a same-config re-install shares the scope). A killed seat names
/// the calendar from its setup; a removed one from the row's own strings, which a side-table
/// write may hold as custody handles.
fn held_rows_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    event: &EntityId,
) -> crate::Result<Vec<HeldOutboxRow>> {
    let releases = OutboxReleases::read_in_txn(vault, txn)?;
    let seats = installed_seat_scopes_in_txn(vault, txn)?;
    let in_service = scopes_in_service(&seats);
    let mut held = Vec::new();
    for (_, row) in OUTBOX.scan_from(&vault.store, txn, OUTBOX_ROW_TAG)? {
        if !holds_pulls(&row)
            || !writes_event(&row, event)
            || in_service.contains(&row.carrier.seat)
            || releases.released(&row)?
        {
            continue;
        }
        let (seat, system, calendar_ref) =
            match seats.iter().find(|seat| seat.scope == row.carrier.seat) {
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
        let revision = revision(&row)?;
        held.push(HeldOutboxRow {
            outbox_id: row.outbox_id,
            revision,
            view: CalendarHoldRow {
                system,
                calendar_ref,
                seat,
                sequence: row.sequence,
                outbox_id: bytes_to_hex_lower(&row.outbox_id),
                instance: bytes_to_hex_lower(&row.carrier.instance),
                updated_at: row.updated_at,
                revision: bytes_to_hex_lower(&revision),
                releasable: !stages_first_write(vault, txn, &row)?,
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
/// proof, which the writer revalidates: one mark per releasable held row, naming its revision as
/// it stands, dated on the vault's recording clock. A first write's row stays held
/// ([`stages_first_write`]). `false`, writing nothing, when the holds read now are not exactly
/// those shown (a row moved, settled or was released since the preview), or none of them is
/// releasable.
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
        if !held.iter().any(|row| row.view.releasable)
            || !held.iter().map(|row| &row.view).eq(shown.iter())
        {
            return Ok(false);
        }
        for row in held.iter().filter(|row| row.view.releasable) {
            RELEASES.put(
                &vault.store,
                wtxn,
                &row.outbox_id,
                &ReleasedOutboxRow {
                    revision: row.revision,
                    released_at: now,
                },
            )?;
        }
        Ok(true)
    })?;
    Ok(released)
}

/// Records a host cancel of `event`, seen at `now`, as a cancel Oneiron cannot attribute when
/// the owner released a hold of `event` that still stands as released: the cancel cannot be
/// told from that row's write coming back, so the owner's line asks "a cancel we can't
/// attribute: refund by hand?" and no money moves (CAL-OUTBOX-ROW-OF-REMOVED-SEAT-HOLDS-PULLS
/// = C). The line travels as the replay-evidence claim of the released row, naming the
/// SEQUENCE it staged ([`record_replay_cancel_evidence_in_txn`]), so the node that holds the
/// booking's live deposit reads it, after a home move too (BK-REPLAY-NOTE-DELIVERY = A). The
/// release is read in the same writer. Returns whether a released hold stands; on `false` the
/// caller refunds.
///
/// # Errors
///
/// Storage failures; a claim the calendar import door refuses.
pub(crate) fn record_released_hold_cancel(
    vault: &Vault,
    event: &EntityId,
    now: u64,
) -> Result<bool, CalendarError> {
    vault
        .try_with_write_txn_grouped(|wtxn| -> Result<bool, CalendarConnectorError> {
            let releases = OutboxReleases::read_in_txn(vault, &*wtxn)?;
            let mut released = None;
            for (_, row) in OUTBOX.scan_from(&vault.store, &*wtxn, OUTBOX_ROW_TAG)? {
                if holds_pulls(&row) && writes_event(&row, event) && releases.released(&row)? {
                    released = Some((row.outbox_id, row.sequence));
                    break;
                }
            }
            let Some((outbox_id, sequence)) = released else {
                return Ok(false);
            };
            record_replay_cancel_evidence_in_txn(vault, wtxn, *event, &outbox_id, sequence, now)?;
            Ok(true)
        })
        .map_err(|error| match error {
            CalendarConnectorError::Calendar(error) => error,
            other => CalendarError::IcsIngest {
                reason: other.to_string(),
            },
        })
}
