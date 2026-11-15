//! BK-09: logged owner instructions, real solver proposals, and resumable
//! emergency revisions. Lifecycle owns all booking and passport mutations;
//! CAL owns payloads and outcomes; outbound owns freezing, gates, and effects.

use oneiron_contracts::fingerprint::purposes;
use serde::{Deserialize, Serialize};

#[cfg(test)]
use crate::booking::BOOKING_PASSPORT_SYSTEM;
use crate::booking::lifecycle::{booking_writer, hex_lower};
use crate::booking::{
    BOOKING_EVENT_TYPE_REF_PREDICATE, BOOKING_SOURCE_PAGE_PREDICATE, BOOKING_STATUS_PREDICATE,
    BookingError, BookingEventTypeRefValue, BookingSourcePageValue, BookingStatus,
    BookingStatusValue, CalendarRevision, EventTypeKey,
};
#[cfg(test)]
use crate::calendar::passport::live_passports_for_event;
use crate::calendar::query::{CalendarRead, visit_calendar_events_for_effect};
use crate::claim::{ClaimSubject, claim_surfaceable};
use crate::side_table::{self, LegacyJson, SideTable};
use crate::temporal::TimeRange;
use crate::{EntityId, Vault};

/// Lane-owned explicit instruction rows. The suffix is the five-field content
/// hash, not the three-field request verification hash.
pub const EMERGENCY_INSTRUCTION_META_PREFIX: &[u8] = b"booking:emergency_instruction:v1:";

/// One logged owner instruction. Key: hex64 (the five-field content hash
/// [`instruction_key`] spells).
const INSTRUCTION: SideTable<String, OwnerInstructionRecord, LegacyJson> =
    SideTable::new(&side_table::EMERGENCY_INSTRUCTION);

/// The [`INSTRUCTION`] table key: the hex suffix after a full raw
/// `instruction_key`/`request_instruction_key` row key. `None` for a key
/// under a foreign prefix or non-UTF8 suffix — never an error, matching this
/// door's old "absent" behavior for an unrecognized key.
fn instruction_hex(key: &[u8]) -> Option<&str> {
    std::str::from_utf8(key.strip_prefix(EMERGENCY_INSTRUCTION_META_PREFIX)?).ok()
}

#[doc(hidden)]
pub use oneiron_records::booking::emergency_reschedule::{
    EmergencyActionPolicy, EmergencyRescheduleRequest, OwnerInstructionRecord,
};
#[doc(hidden)]
use oneiron_records::booking::emergency_reschedule::{
    content_hash, entity_ref_serde, refused, storage_failure, time_range_serde,
};

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
    content_hash(
        purposes::booking::EMERGENCY_REQUEST_HASH,
        &request_fields(window, reason, action_policy)?,
    )
}

fn instruction_key(
    owner_ref: EntityId,
    window: TimeRange,
    reason: &str,
    action_policy: EmergencyActionPolicy,
    recorded_at: u64,
) -> Result<Vec<u8>, BookingError> {
    let digest = content_hash(
        purposes::booking::EMERGENCY_INSTRUCTION_KEY,
        &InstructionFields {
            owner_ref: owner_ref.to_hex(),
            request: request_fields(window, reason, action_policy)?,
            recorded_at,
        },
    )?;
    let mut key = EMERGENCY_INSTRUCTION_META_PREFIX.to_vec();
    key.extend_from_slice(hex_lower(&digest).as_bytes());
    Ok(key)
}

/// An instruction's full raw row key.
#[cfg(oneiron_test_support)]
pub(crate) fn instruction_key_for_test(
    owner_ref: EntityId,
    window: TimeRange,
    reason: &str,
    action_policy: EmergencyActionPolicy,
    recorded_at: u64,
) -> Result<Vec<u8>, BookingError> {
    instruction_key(owner_ref, window, reason, action_policy, recorded_at)
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
    let hex = instruction_hex(&key)
        .ok_or_else(|| refused("emergency instruction key is malformed"))?
        .to_owned();
    booking_writer(vault, |wtxn| {
        if let Some(prior) = INSTRUCTION
            .get(&vault.store, &*wtxn, &hex)
            .map_err(storage_failure)?
        {
            if prior != record {
                return Err(refused("instruction content conflicts with its stored row"));
            }
            return Ok(());
        }
        INSTRUCTION
            .put(&vault.store, wtxn, &hex, &record)
            .map_err(storage_failure)
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
    let hex =
        instruction_hex(&key).ok_or_else(|| refused("owner instruction has not been logged"))?;
    let rtxn = vault.store.env.read_txn().map_err(storage_failure)?;
    let stored = INSTRUCTION
        .get(&vault.store, &rtxn, &hex.to_owned())
        .map_err(storage_failure)?
        .ok_or_else(|| refused("owner instruction has not been logged"))?;
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
    let hex =
        instruction_hex(&key).ok_or_else(|| refused("emergency instruction key is malformed"))?;
    if let Some(prior) = INSTRUCTION
        .get(&vault.store, &*wtxn, &hex.to_owned())
        .map_err(storage_failure)?
    {
        if prior != request.authority {
            return Err(refused("instruction content conflicts with its stored row"));
        }
        return Ok(());
    }
    INSTRUCTION
        .put(&vault.store, wtxn, &hex.to_owned(), &request.authority)
        .map_err(storage_failure)
}

fn request_instruction_key(request: &EmergencyRescheduleRequest) -> Result<Vec<u8>, BookingError> {
    instruction_key(
        request.owner_ref,
        request.affected_window,
        &request.reason,
        request.action_policy,
        request.authority.recorded_at,
    )
}

fn verify_instruction_in_txn(
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
    let key = request_instruction_key(request)?;
    let hex =
        instruction_hex(&key).ok_or_else(|| refused("owner instruction has not been logged"))?;
    let stored = INSTRUCTION
        .get(&vault.store, txn, &hex.to_owned())
        .map_err(storage_failure)?
        .ok_or_else(|| refused("owner instruction has not been logged"))?;
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

pub(super) fn calendar_failure(error: crate::calendar::CalendarError) -> BookingError {
    match error {
        crate::calendar::CalendarError::InviteRefused { reason } => {
            BookingError::InvalidConfig(reason)
        }
        other => storage_failure(other),
    }
}

mod lookup;
mod state;
#[cfg(oneiron_test_support)]
pub(crate) use lookup::request_plan_hash_for_test;
pub(crate) use state::{
    ensure_no_pending_effect_in, pending_effect_fences_in, verify_frozen_effect_in,
};
use state::{persist_content_in, verify_owner_home_in};

mod enumeration;
mod execution;
mod pick;
mod planning;

use enumeration::enumerate_with_refusals;
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
