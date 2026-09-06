//! BK-09: logged owner instructions, real solver proposals, and resumable
//! emergency revisions. Lifecycle owns all booking and passport mutations;
//! CAL owns payloads and outcomes; outbound owns freezing, gates, and effects.

use serde::{Deserialize, Serialize};

#[cfg(test)]
use crate::booking::BOOKING_PASSPORT_SYSTEM;
use crate::booking::lifecycle::{booking_writer, hex_lower, put_meta, read_meta_bytes};
use crate::booking::{
    BOOKING_EVENT_TYPE_REF_PREDICATE, BOOKING_SOURCE_PAGE_PREDICATE, BOOKING_STATUS_PREDICATE,
    BookingError, BookingEventTypeRefValue, BookingSourcePageValue, BookingStatus,
    BookingStatusValue, CalendarRevision, EventTypeKey,
};
#[cfg(test)]
use crate::calendar::passport::live_passports_for_event;
use crate::calendar::query::{CalendarRead, visit_calendar_events};
use crate::claim::{ClaimSubject, claim_surfaceable};
use crate::temporal::TimeRange;
use crate::{EntityId, Vault};

/// Lane-owned explicit instruction rows. The suffix is the five-field content
/// hash, not the three-field request verification hash.
pub const EMERGENCY_INSTRUCTION_META_PREFIX: &[u8] = b"booking:emergency_instruction:v1:";

/// The owner chooses the action; discovery cannot silently change it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EmergencyActionPolicy {
    Cancel,
    RequestUpdate,
}

/// One logged instruction. This is a reference to durable evidence, not proof
/// by itself. The host must authenticate the owner before calling append.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnerInstructionRecord {
    #[serde(with = "entity_ref_serde")]
    pub owner_ref: EntityId,
    pub request_hash: [u8; 32],
    pub recorded_at: u64,
}

/// Executing request. `affected_window` is inclusive, like core `TimeRange`;
/// booking occurrences exposed below are half-open, like booking's slot seam.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EmergencyRescheduleRequest {
    #[serde(with = "entity_ref_serde")]
    pub owner_ref: EntityId,
    #[serde(with = "time_range_serde")]
    pub affected_window: TimeRange,
    pub reason: String,
    pub action_policy: EmergencyActionPolicy,
    pub authority: OwnerInstructionRecord,
}

#[derive(Serialize)]
struct WindowFields {
    start: u64,
    end: u64,
}

#[derive(Serialize)]
struct RequestFields<'a> {
    window: WindowFields,
    reason: &'a str,
    action_policy: EmergencyActionPolicy,
}

#[derive(Serialize)]
struct InstructionFields<'a> {
    owner_ref: String,
    #[serde(flatten)]
    request: RequestFields<'a>,
    recorded_at: u64,
}

fn request_fields(
    window: TimeRange,
    reason: &str,
    action_policy: EmergencyActionPolicy,
) -> Result<RequestFields<'_>, BookingError> {
    if window.start > window.end || reason.trim().is_empty() || reason.len() > 4096 {
        return Err(BookingError::InvalidConstraint(
            "instruction requires an ordered window and a 1..=4096 byte reason".to_owned(),
        ));
    }
    Ok(RequestFields {
        window: WindowFields {
            start: window.start,
            end: window.end,
        },
        reason,
        action_policy,
    })
}

fn content_hash(value: &impl Serialize) -> Result<[u8; 32], BookingError> {
    let bytes = serde_json::to_vec(value).map_err(storage_failure)?;
    Ok(*blake3::hash(&bytes).as_bytes())
}

/// Canonical hash of exactly `{window, reason, action_policy}` in that order.
/// Whitespace in the reason is preserved, never normalized into another request.
///
/// # Errors
/// Refuses an inverted window, blank/oversized reason, or encoding failure.
pub fn canonical_emergency_request_hash(
    window: TimeRange,
    reason: &str,
    action_policy: EmergencyActionPolicy,
) -> Result<[u8; 32], BookingError> {
    content_hash(&request_fields(window, reason, action_policy)?)
}

fn instruction_key(
    owner_ref: EntityId,
    window: TimeRange,
    reason: &str,
    action_policy: EmergencyActionPolicy,
    recorded_at: u64,
) -> Result<Vec<u8>, BookingError> {
    let digest = content_hash(&InstructionFields {
        owner_ref: owner_ref.to_hex(),
        request: request_fields(window, reason, action_policy)?,
        recorded_at,
    })?;
    let mut key = EMERGENCY_INSTRUCTION_META_PREFIX.to_vec();
    key.extend_from_slice(hex_lower(&digest).as_bytes());
    Ok(key)
}

/// Appends an explicit, authenticated owner instruction and reads it back.
///
/// The caller is the host's owner-instruction door, not a counterparty endpoint.
/// Repeating the exact append is a no-op. Existing conflicting bytes fail closed.
/// No authority ledger or lifecycle state is written by this door.
///
/// # Errors
/// Invalid instruction, conflicting content, or persistent-store failure.
#[cfg(test)]
fn append_owner_instruction(
    vault: &Vault,
    owner_ref: EntityId,
    window: TimeRange,
    reason: &str,
    action_policy: EmergencyActionPolicy,
    recorded_at: u64,
) -> Result<OwnerInstructionRecord, BookingError> {
    let record = OwnerInstructionRecord {
        owner_ref,
        request_hash: canonical_emergency_request_hash(window, reason, action_policy)?,
        recorded_at,
    };
    let key = instruction_key(owner_ref, window, reason, action_policy, recorded_at)?;
    let encoded = serde_json::to_vec(&record).map_err(storage_failure)?;
    booking_writer(vault, |wtxn| {
        if let Some(prior) = read_meta_bytes(vault, &*wtxn, &key)? {
            if prior != encoded {
                return Err(refused("instruction content conflicts with its stored row"));
            }
            return Ok(());
        }
        put_meta(vault, wtxn, &key, &encoded)
    })?;
    // Separate read after commit: an in-memory record alone is never authority.
    verify_logged_owner_instruction(
        vault,
        &EmergencyRescheduleRequest {
            owner_ref,
            affected_window: window,
            reason: reason.to_owned(),
            action_policy,
            authority: record.clone(),
        },
    )?;
    Ok(record)
}

/// Reads the five-field content-addressed row and verifies the executing owner
/// plus canonical three-field request hash. Every discovery/effect door must
/// call this; possession of a stable row key cannot replace the comparison.
///
/// # Errors
/// Missing row, any authority/request mutation, malformed row, or storage error.
pub fn verify_logged_owner_instruction(
    vault: &Vault,
    request: &EmergencyRescheduleRequest,
) -> Result<(), BookingError> {
    let expected = canonical_emergency_request_hash(
        request.affected_window,
        &request.reason,
        request.action_policy,
    )?;
    if request.authority.owner_ref != request.owner_ref
        || request.authority.request_hash != expected
    {
        return Err(refused(
            "instruction does not bind this owner and executing request",
        ));
    }
    let key = instruction_key(
        request.authority.owner_ref,
        request.affected_window,
        &request.reason,
        request.action_policy,
        request.authority.recorded_at,
    )?;
    let rtxn = vault.store.env.read_txn().map_err(storage_failure)?;
    let raw = read_meta_bytes(vault, &rtxn, &key)?
        .ok_or_else(|| refused("owner instruction has not been logged"))?;
    let stored: OwnerInstructionRecord = serde_json::from_slice(&raw).map_err(storage_failure)?;
    if stored != request.authority
        || stored.owner_ref != request.owner_ref
        || stored.request_hash != expected
    {
        return Err(refused(
            "stored instruction does not bind this executing request",
        ));
    }
    Ok(())
}

pub(crate) fn append_instruction_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    request: &EmergencyRescheduleRequest,
) -> Result<(), BookingError> {
    verify_owner_home_in(vault, wtxn, request.owner_ref)?;
    let expected = canonical_emergency_request_hash(
        request.affected_window,
        &request.reason,
        request.action_policy,
    )?;
    if request.authority.owner_ref != request.owner_ref
        || request.authority.request_hash != expected
    {
        return Err(refused(
            "instruction does not bind the executing owner and request",
        ));
    }
    let key = request_instruction_key(request)?;
    let encoded = serde_json::to_vec(&request.authority).map_err(storage_failure)?;
    if let Some(prior) = read_meta_bytes(vault, &*wtxn, &key)? {
        if prior != encoded {
            return Err(refused("instruction content conflicts with its stored row"));
        }
        return Ok(());
    }
    put_meta(vault, wtxn, &key, &encoded)
}

pub(crate) fn request_instruction_key(
    request: &EmergencyRescheduleRequest,
) -> Result<Vec<u8>, BookingError> {
    instruction_key(
        request.owner_ref,
        request.affected_window,
        &request.reason,
        request.action_policy,
        request.authority.recorded_at,
    )
}

pub(crate) fn verify_instruction_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    request: &EmergencyRescheduleRequest,
) -> Result<(), BookingError> {
    verify_owner_home_in(vault, txn, request.owner_ref)?;
    let expected = canonical_emergency_request_hash(
        request.affected_window,
        &request.reason,
        request.action_policy,
    )?;
    let raw = read_meta_bytes(vault, txn, &request_instruction_key(request)?)?
        .ok_or_else(|| refused("owner instruction has not been logged"))?;
    let stored: OwnerInstructionRecord = serde_json::from_slice(&raw).map_err(storage_failure)?;
    if stored != request.authority
        || stored.owner_ref != request.owner_ref
        || stored.request_hash != expected
    {
        return Err(refused(
            "stored instruction does not bind this executing request",
        ));
    }
    Ok(())
}

mod time_range_serde {
    use super::*;
    pub(super) fn serialize<S: serde::Serializer>(
        value: &TimeRange,
        s: S,
    ) -> Result<S::Ok, S::Error> {
        (value.start, value.end).serialize(s)
    }
    pub(super) fn deserialize<'de, D: serde::Deserializer<'de>>(
        d: D,
    ) -> Result<TimeRange, D::Error> {
        let (start, end) = <(u64, u64)>::deserialize(d)?;
        Ok(TimeRange { start, end })
    }
}

fn refused(reason: &str) -> BookingError {
    BookingError::InvalidConfig(reason.to_owned())
}

pub(crate) fn calendar_failure(error: crate::calendar::CalendarError) -> BookingError {
    match error {
        crate::calendar::CalendarError::InviteRefused { reason } => {
            BookingError::InvalidConfig(reason)
        }
        other => storage_failure(other),
    }
}

fn storage_failure(error: impl std::fmt::Display) -> BookingError {
    BookingError::SlotOracle(format!("emergency reschedule: {error}"))
}

mod entity_ref_serde {
    use super::*;

    pub(super) fn serialize<S: serde::Serializer>(
        value: &EntityId,
        s: S,
    ) -> Result<S::Ok, S::Error> {
        s.serialize_str(&value.to_hex())
    }

    pub(super) fn deserialize<'de, D: serde::Deserializer<'de>>(
        d: D,
    ) -> Result<EntityId, D::Error> {
        EntityId::from_hex(&String::deserialize(d)?).map_err(serde::de::Error::custom)
    }
}

mod state;
pub(crate) use state::{ensure_no_pending_effect_in, verify_frozen_effect_in};
use state::{persist_content_in, verify_owner_home_in};

mod enumeration;
mod execution;
mod pick;
mod planning;

use enumeration::enumerate_with_refusals;
#[cfg(test)]
use enumeration::read_fact;
pub use enumeration::{AffectedBooking, enumerate_affected_bookings};
pub use execution::execute_emergency_plan;
pub use pick::{EmergencyPick, counterparty_pick};
pub(crate) use pick::{verify_pick_blob, verify_pick_invite_in};
use planning::blob_id;
#[cfg(test)]
use planning::plan_item;
pub use planning::{
    EMERGENCY_ITEM_META_PREFIX, EMERGENCY_PLAN_META_PREFIX, EmergencyBatchPlan, EmergencyItem,
    EmergencyLocalBasis, EmergencyPlan, plan_emergency_reschedule,
};
pub(crate) use planning::{
    item_key, read_item_in, solve_live, verify_initial_invite_in, verify_plan_blob, verify_plan_in,
    write_item_in,
};

#[cfg(test)]
mod tests;
