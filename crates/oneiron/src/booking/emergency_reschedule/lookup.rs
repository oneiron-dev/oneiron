//! Disposable lookup rows derived from the existing plans and checkpoints.
//! They grant no authority: readers still validate the referenced receipt.

use super::*;
use crate::attempt_queue::AttemptId;
use crate::side_table::{self, Raw, SideTable};

/// Kept for tests that build a scan prefix directly; production scans go
/// through [`REQUEST_PLAN_INDEX`].
#[cfg(test)]
const REQUEST_PLAN_PREFIX: &[u8] = b"booking:emergency_request_plan:v1:";

/// Pending-event pointer to a checkpoint's full raw key. Key: id16 (event).
const PENDING_EVENT: SideTable<EntityId, Vec<u8>, Raw> =
    SideTable::new(&side_table::EMERGENCY_PENDING_EVENT_LOOKUP);

/// Effect-attempt pointer to a checkpoint's full raw key. Key: id16 (attempt).
const EFFECT: SideTable<[u8; 16], Vec<u8>, Raw> =
    SideTable::new(&side_table::EMERGENCY_EFFECT_LOOKUP);

/// Instruction-to-plan posting-list row, value = the plan's full raw key. Key:
/// hash32 (the instruction content hash) + id16 (event).
pub(super) const REQUEST_PLAN_INDEX: SideTable<([u8; 32], EntityId), Vec<u8>, Raw> =
    SideTable::new(&side_table::EMERGENCY_REQUEST_PLAN_INDEX);

/// Kept for tests that build a scan prefix directly; production scans go
/// through [`REQUEST_PLAN_INDEX`].
#[cfg(test)]
pub(super) fn request_plan_prefix(
    request: &EmergencyRescheduleRequest,
) -> Result<Vec<u8>, BookingError> {
    let mut key = REQUEST_PLAN_PREFIX.to_vec();
    key.extend_from_slice(&content_hash(&request_instruction_key(request)?)?);
    Ok(key)
}

/// The instruction content hash [`request_plan_prefix`] spells, for the typed
/// [`REQUEST_PLAN_INDEX`] table's own key.
pub(super) fn request_plan_hash(
    request: &EmergencyRescheduleRequest,
) -> Result<[u8; 32], BookingError> {
    content_hash(&request_instruction_key(request)?)
}

/// Scans every plan indexed for this instruction, in key (event) order. Key:
/// id16 (event); value: the plan's full raw row key.
pub(super) fn request_plan_rows(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    request: &EmergencyRescheduleRequest,
) -> Result<Vec<(EntityId, Vec<u8>)>, BookingError> {
    let hash = request_plan_hash(request)?;
    Ok(REQUEST_PLAN_INDEX
        .scan_from(&vault.store, txn, &hash)
        .map_err(storage_failure)?
        .into_iter()
        .map(|((_, event), key)| (event, key))
        .collect())
}

/// The index key identifies a refused event even if its target cannot be read.
/// An invalid key cannot safely be attributed to any booking. Kept for tests
/// that still exercise the raw key shape directly.
#[cfg(test)]
pub(super) fn request_plan_event(prefix: &[u8], key: &[u8]) -> Result<EntityId, BookingError> {
    let bytes: [u8; 16] = key
        .strip_prefix(prefix)
        .and_then(|suffix| suffix.try_into().ok())
        .ok_or_else(|| refused("emergency plan lookup has no valid event key"))?;
    EntityId::from_bytes(bytes).map_err(|_| refused("emergency plan lookup has no valid event key"))
}

pub(super) fn index_plan_in(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    plan: &EmergencyPlan,
    plan_key: &[u8],
) -> Result<(), BookingError> {
    let key = (
        request_plan_hash(&plan.request)?,
        plan.booking.calendar.event_ref,
    );
    REQUEST_PLAN_INDEX
        .put(&vault.store, txn, &key, &plan_key.to_vec())
        .map_err(storage_failure)
}

pub(super) fn pending_revision(item: &EmergencyItem) -> Option<&CalendarRevision> {
    match &item.picked {
        Some(picked) => (!picked.calendar_delivered).then_some(&picked.calendar),
        None => (!item.calendar_delivered || !item.apology_delivered).then_some(&item.calendar),
    }
}

/// Called only by the existing checkpoint writer, in its transaction. The
/// pending event pointer disappears with completion; the historical receipt
/// remains. Effect pointers remain direct lookups so even a reconstructed
/// completed call cannot lose its emergency classification when bytes corrupt.
pub(super) fn index_item_in(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    item: &EmergencyItem,
    item_key: &[u8],
) -> Result<(), BookingError> {
    let event = item.calendar.event_ref;
    if pending_revision(item).is_some() {
        PENDING_EVENT
            .put(&vault.store, txn, &event, &item_key.to_vec())
            .map_err(storage_failure)?;
    } else if PENDING_EVENT
        .get(&vault.store, txn, &event)
        .map_err(storage_failure)?
        .as_deref()
        == Some(item_key)
    {
        PENDING_EVENT
            .delete(&vault.store, txn, &event)
            .map_err(storage_failure)?;
    }
    let mut effects = vec![("apology", item.plan.content_hash)];
    if item.plan.payload.is_some() {
        effects.push(("calendar", item.plan.content_hash));
    }
    if let Some(picked) = &item.picked {
        effects.push(("pick", picked.content_hash));
    }
    for (lane, hash) in effects {
        let reference = state::effect_ref(item, lane, hash)?;
        let attempt =
            crate::outbound::outbound_dispatch_attempt_id(&reference).map_err(storage_failure)?;
        EFFECT
            .put(&vault.store, txn, attempt.as_bytes(), &item_key.to_vec())
            .map_err(storage_failure)?;
    }
    Ok(())
}

fn indexed_item_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    target: Option<Vec<u8>>,
) -> Result<Option<EmergencyItem>, BookingError> {
    let Some(target) = target else {
        return Ok(None);
    };
    if !target.starts_with(EMERGENCY_ITEM_META_PREFIX) {
        return Err(refused("emergency lookup does not name a checkpoint"));
    }
    let item = read_item_in(vault, txn, &target)?
        .ok_or_else(|| refused("indexed emergency checkpoint is missing"))?;
    if item_key(&item.plan.request, item.calendar.event_ref)? != target {
        return Err(refused("emergency lookup conflicts with its checkpoint"));
    }
    Ok(Some(item))
}

pub(super) fn pending_event_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    event: EntityId,
) -> Result<Option<EmergencyItem>, BookingError> {
    let target = PENDING_EVENT
        .get(&vault.store, txn, &event)
        .map_err(storage_failure)?;
    let item = indexed_item_in(vault, txn, target)?;
    if item
        .as_ref()
        .is_some_and(|item| item.calendar.event_ref != event)
    {
        return Err(refused("pending emergency lookup names another event"));
    }
    Ok(item)
}

pub(super) fn effect_item_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    attempt: AttemptId,
) -> Result<Option<EmergencyItem>, BookingError> {
    let target = EFFECT
        .get(&vault.store, txn, attempt.as_bytes())
        .map_err(storage_failure)?;
    indexed_item_in(vault, txn, target)
}
