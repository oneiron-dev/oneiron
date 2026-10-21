//! What each runner seat's quota last read as (OF-137), kept by the route so
//! a pass picks seats without reading an exhaust again.
//!
//! A seat is its runner, its sign-in and its custody handles, so two
//! policies that order the same seat share its quota. A spent capture on a
//! seat appends the refusal the whole-exhaust scan read (or the host's typed
//! [`super::ByoaError::SeatSpent`]); a completed run on a spent seat appends
//! its clearing. The head is the seat's quota. Numbers and references only:
//! a login seat's record names no credential, a key seat's names handles.

use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::attempt_queue::{AttemptRecord, AttemptState};
use crate::codebase::entity_id_from_hash_material;
use crate::entity_id::EntityId;
use crate::error::Error;

use super::connector::BYOA_ATTEMPT_KIND;
use super::error::ByoaResult;
use super::record::{append_record_in_txn, head_record};
use super::seat::{RunnerSeat, RunnerSeatPolicy, SeatAuth, SeatSpent};

/// Domain a seat's quota record id is derived under.
const SEAT_QUOTA_DOMAIN: &[u8] = b"oneiron:byoa-runner-seat-quota:v1";

/// Media type of a seat's quota record.
const SEAT_QUOTA_MEDIA_TYPE: &str = "application/vnd.oneiron.byoa-seat-quota+msgpack";

/// One reading of a seat's quota: the capture that read it, the refusal it
/// read (none clears a spend) and that capture's settle time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct SeatQuotaRecord {
    attempt: [u8; 16],
    spent: Option<SeatSpent>,
    observed_at: u64,
}

/// One seat's quota as its captures last read it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunnerSeatQuota {
    /// The seat's index in the owner's order.
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
}

/// The id a seat's quota record lives under.
fn seat_quota_id(seat: &RunnerSeat) -> ByoaResult<EntityId> {
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
    };
    if head
        .as_ref()
        .is_some_and(|head| head.attempt == record.attempt || head.observed_at > record.observed_at)
    {
        return Ok(());
    }
    append_record_in_txn(
        vault,
        wtxn,
        &id,
        format!("{BYOA_ATTEMPT_KIND}/seat-quota/{}", id.to_hex()),
        SEAT_QUOTA_MEDIA_TYPE,
        &record,
        record.observed_at,
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
        .map(|(index, seat)| {
            let head: Option<SeatQuotaRecord> = head_record(vault, rtxn, &seat_quota_id(seat)?)?;
            let observed_at = head.as_ref().map(|head| head.observed_at);
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
            })
        })
        .collect()
}
