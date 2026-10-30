//! What each runner seat's quota last read as (OF-137), kept by the route so
//! a pass picks seats without reading an exhaust again.
//!
//! A seat is its runner, its sign-in and its custody handles, so two
//! policies that order the same seat share its quota. A spent capture on a
//! seat appends the refusal the whole-exhaust scan read (or the host's typed
//! [`super::ByoaError::SeatSpent`]); a completed run on a spent seat appends
//! its clearing, and so does the owner's word that a seat's spent credit is
//! topped up (FIX 7451). The head is the seat's quota. Numbers and
//! references only: a login seat's record names no credential, a key
//! seat's names handles.

use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::attempt_queue::{AttemptRecord, AttemptState};
use crate::codebase::entity_id_from_hash_material;
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::error::Error;
use crate::llm::SpentKind;

use super::connector::BYOA_ATTEMPT_KIND;
use super::error::ByoaResult;
use super::owner_doors::RunnerSeatTopUpEffect;
use super::record::{append_record_in_txn, head_record, head_record_checked};
use super::seat::{RunnerSeat, RunnerSeatPolicy, SeatAuth, SeatSpent};

/// Domain a seat's quota record id is derived under.
const SEAT_QUOTA_DOMAIN: &[u8] = b"oneiron:byoa-runner-seat-quota:v1";

/// Media type of a seat's quota record.
const SEAT_QUOTA_MEDIA_TYPE: &str = "application/vnd.oneiron.byoa-seat-quota+msgpack";

/// One reading of a seat's quota: the capture that read it, the refusal it
/// read (none clears a spend), that capture's settle time, and the owner's
/// top-up that cleared it, when one did.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct SeatQuotaRecord {
    attempt: [u8; 16],
    spent: Option<SeatSpent>,
    observed_at: u64,
    /// The owner's word that this capture's spent credit is topped up
    /// (FIX 7451). The record keeps the capture it clears, so that
    /// capture's replay never spends the seat again.
    topped_up: Option<OwnerTopUp>,
}

/// The owner's "topped up" (FIX 7451): who said it, the authentication it
/// was said under, and when.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct OwnerTopUp {
    /// The owner's actor id.
    pub(super) owner: [u8; 16],
    /// The Gate decision the owner's authentication is bound to.
    pub(super) decision: [u8; 16],
    /// The vault's time, in seconds.
    pub(super) at: u64,
}

/// One seat's quota as its captures last read it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RunnerSeatQuota {
    /// The seat's index in the owner's order, or in a quota read's request.
    pub seat: usize,
    /// The runner the seat names.
    pub runner: String,
    /// The spent refusal last read on the seat. `None` when none was, or a
    /// completed run on the seat cleared it.
    pub spent: Option<SeatSpent>,
    /// When the last reading was taken: its capture's settle time.
    pub observed_at: Option<u64>,
    /// When a spent seat is back ([`SeatSpent::back_at`] at its reading).
    /// `None` while a spent seat waits for the owner, and for a seat not
    /// spent.
    pub back_at: Option<u64>,
    /// Whether the seat may take work now: not spent, or back by now.
    pub available: bool,
    /// The capture the last reading came from, in lower-case hex: the spent
    /// attempt an owner's top-up names. `None` when no capture recorded one.
    pub last_capture: Option<String>,
    /// When the owner said the seat's spent credit was topped up, when that
    /// cleared its last reading.
    pub topped_up_at: Option<u64>,
}

/// The id a seat's quota record lives under.
pub(super) fn seat_quota_id(seat: &RunnerSeat) -> ByoaResult<EntityId> {
    let auth: &[u8] = match seat.auth {
        SeatAuth::VendorLogin => b"vendor_login",
        SeatAuth::ApiKey => b"api_key",
    };
    let mut parts = vec![seat.runner.as_bytes(), auth];
    parts.extend(
        seat.credential_handles
            .iter()
            .map(|handle| handle.as_str().as_bytes()),
    );
    Ok(entity_id_from_hash_material(SEAT_QUOTA_DOMAIN, &parts)?)
}

/// Records what `attempt`'s capture read of `seat`'s quota, in the routing
/// writer: a spend, or a completed run's clearing of a spent seat. Any other
/// capture proves nothing and records nothing. A replay, and an older
/// capture settling after a newer reading, keep the head.
///
/// # Errors
/// A record that does not encode or decode; a store failure.
pub(super) fn record_seat_quota_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    seat: &RunnerSeat,
    attempt: &AttemptRecord,
    spent: Option<&SeatSpent>,
) -> ByoaResult<()> {
    let id = seat_quota_id(seat)?;
    let head: Option<SeatQuotaRecord> = head_record(vault, wtxn, &id)?;
    let cleared = attempt.state == AttemptState::Completed
        && head.as_ref().is_some_and(|head| head.spent.is_some());
    if spent.is_none() && !cleared {
        return Ok(());
    }
    let record = SeatQuotaRecord {
        attempt: *attempt.id.as_bytes(),
        spent: spent.cloned(),
        observed_at: attempt.updated_at,
        topped_up: None,
    };
    if head
        .as_ref()
        .is_some_and(|head| head.attempt == record.attempt || head.observed_at > record.observed_at)
    {
        return Ok(());
    }
    append_quota_in_txn(vault, wtxn, &id, &record, record.observed_at)
}

/// Clears `seat`'s quota on the owner's word that its spent credit is
/// topped up (FIX 7451), in the owner's writer: only while its last reading
/// is the capture `expected` and that reading is a credit spend. The
/// clearing keeps that capture and its time and adds the owner's top-up,
/// so the capture's replay never spends the seat again and a later spend
/// is still read. A second top-up, a stale one, and a reading that is no
/// credit spend write nothing.
///
/// # Errors
/// A record that does not encode or decode; a store failure.
pub(super) fn top_up_seat_quota_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    seat: &RunnerSeat,
    expected: [u8; 16],
    top_up: OwnerTopUp,
) -> ByoaResult<RunnerSeatTopUpEffect> {
    let id = seat_quota_id(seat)?;
    let head: Option<SeatQuotaRecord> = head_record(vault, wtxn, &id)?;
    let Some(head) = head.filter(|head| head.attempt == expected) else {
        return Ok(RunnerSeatTopUpEffect::ObservationChanged);
    };
    let credit = match &head.spent {
        None => return Ok(RunnerSeatTopUpEffect::AlreadyClear),
        Some(spent) => spent.kind == Some(SpentKind::Credit),
    };
    if !credit {
        return Ok(RunnerSeatTopUpEffect::NotCredit);
    }
    let record = SeatQuotaRecord {
        spent: None,
        topped_up: Some(top_up),
        ..head
    };
    append_quota_in_txn(vault, wtxn, &id, &record, top_up.at)?;
    Ok(RunnerSeatTopUpEffect::Cleared)
}

/// Appends `record` as the head of the quota record `id`.
fn append_quota_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    record: &SeatQuotaRecord,
    now: u64,
) -> ByoaResult<()> {
    append_record_in_txn(
        vault,
        wtxn,
        id,
        format!("{BYOA_ATTEMPT_KIND}/seat-quota/{}", id.to_hex()),
        SEAT_QUOTA_MEDIA_TYPE,
        record,
        now,
    )
}

/// Each seat's quota in the owner's order, at `now`, as the seat's captures
/// recorded it: the whole-exhaust scan's reading, never a second read of an
/// exhaust. A seat no capture recorded is available.
///
/// # Errors
/// A record that does not decode; a store failure.
pub fn runner_seat_quotas(
    vault: &Vault,
    policy: &RunnerSeatPolicy,
    now: u64,
) -> ByoaResult<Vec<RunnerSeatQuota>> {
    let rtxn = vault.store.env.read_txn().map_err(Error::from)?;
    seat_quotas_in_txn(vault, &rtxn, policy, now)
}

/// [`runner_seat_quotas`] in the caller's snapshot.
pub(super) fn seat_quotas_in_txn(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    policy: &RunnerSeatPolicy,
    now: u64,
) -> ByoaResult<Vec<RunnerSeatQuota>> {
    policy
        .seats
        .iter()
        .enumerate()
        .map(|(index, seat)| seat_quota_in_txn(vault, rtxn, index, seat, now))
        .collect()
}

/// `seat`'s quota at `now`, as the seat at `index`, in the caller's
/// snapshot: the head of its record, whatever policy orders it. A head that
/// does not decode counts as unavailable (FIX 11651), never available.
///
/// # Errors
/// A store failure.
pub(super) fn seat_quota_in_txn(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    index: usize,
    seat: &RunnerSeat,
    now: u64,
) -> ByoaResult<RunnerSeatQuota> {
    let checked: Option<ByoaResult<SeatQuotaRecord>> =
        head_record_checked(vault, rtxn, &seat_quota_id(seat)?)?;
    // FIX 11651: a corrupt quota head fails closed as unavailable, the
    // pre-#4170 behavior via `available`, not via a propagated error, so
    // the landed capture keeps its existing skip/park routing.
    let head: Option<SeatQuotaRecord> = match checked {
        None => None,
        Some(Ok(head)) => Some(head),
        Some(Err(_)) => {
            return Ok(RunnerSeatQuota {
                seat: index,
                runner: seat.runner.clone(),
                available: false,
                spent: None,
                observed_at: None,
                back_at: None,
                last_capture: None,
                topped_up_at: None,
            });
        }
    };
    let observed_at = head.as_ref().map(|head| head.observed_at);
    let last_capture = head.as_ref().map(|head| bytes_to_hex_lower(&head.attempt));
    let topped_up_at = head
        .as_ref()
        .and_then(|head| head.topped_up)
        .map(|top_up| top_up.at);
    let spent = head.and_then(|head| head.spent);
    let back_at = spent
        .as_ref()
        .zip(observed_at)
        .and_then(|(spent, at)| spent.back_at(at));
    Ok(RunnerSeatQuota {
        seat: index,
        runner: seat.runner.clone(),
        available: spent.is_none() || back_at.is_some_and(|at| at <= now),
        spent,
        observed_at,
        back_at,
        last_capture,
        topped_up_at,
    })
}
