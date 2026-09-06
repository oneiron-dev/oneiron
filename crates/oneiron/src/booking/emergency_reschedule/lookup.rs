//! Disposable lookup rows derived from the existing plans and checkpoints.
//! They grant no authority: readers still validate the referenced receipt.

use super::*;
use crate::attempt_queue::AttemptId;

const PENDING_EVENT_PREFIX: &[u8] = b"booking:emergency_pending_event:v1:";
const EFFECT_PREFIX: &[u8] = b"booking:emergency_effect:v1:";
const REQUEST_PLAN_PREFIX: &[u8] = b"booking:emergency_request_plan:v1:";

fn event_key(event: EntityId) -> Vec<u8> {
    let mut key = PENDING_EVENT_PREFIX.to_vec();
    key.extend_from_slice(event.as_bytes());
    key
}

fn effect_key(attempt: AttemptId) -> Vec<u8> {
    let mut key = EFFECT_PREFIX.to_vec();
    key.extend_from_slice(attempt.as_bytes());
    key
}

pub(super) fn request_plan_prefix(
    request: &EmergencyRescheduleRequest,
) -> Result<Vec<u8>, BookingError> {
    let mut key = REQUEST_PLAN_PREFIX.to_vec();
    key.extend_from_slice(&content_hash(&request_instruction_key(request)?)?);
    Ok(key)
}

/// The index key identifies a refused event even if its target cannot be read.
/// An invalid key cannot safely be attributed to any booking.
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
    let mut key = request_plan_prefix(&plan.request)?;
    key.extend_from_slice(plan.booking.calendar.event_ref.as_bytes());
    put_meta(vault, txn, &key, plan_key)
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
    let key = event_key(item.calendar.event_ref);
    if pending_revision(item).is_some() {
        put_meta(vault, txn, &key, item_key)?;
    } else if read_meta_bytes(vault, txn, &key)?.as_deref() == Some(item_key) {
        vault
            .store
            .vault_meta
            .delete(txn, &key)
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
        put_meta(vault, txn, &effect_key(attempt), item_key)?;
    }
    Ok(())
}

fn indexed_item_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    key: &[u8],
) -> Result<Option<EmergencyItem>, BookingError> {
    let Some(target) = read_meta_bytes(vault, txn, key)? else {
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
    let item = indexed_item_in(vault, txn, &event_key(event))?;
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
    indexed_item_in(vault, txn, &effect_key(attempt))
}
