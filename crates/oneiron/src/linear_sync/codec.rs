//! Stable link keys, operation/event digests, field hashes.

use crate::entity_id::EntityId;

use super::model::{
    LINEAR_SYNC_EVENT_DOMAIN, LINEAR_SYNC_FIELD_DOMAIN, LINEAR_SYNC_LINK_KEY_PREFIX,
    LINEAR_SYNC_OPERATION_DOMAIN, LINEAR_SYNC_SCHEMA_VERSION, LinearSyncDirection,
};

/// The durable storage key of one TASK ↔ issue link row.
#[must_use]
pub fn linear_sync_link_key(task_ref: EntityId) -> Vec<u8> {
    let mut key = Vec::with_capacity(LINEAR_SYNC_LINK_KEY_PREFIX.len() + 16);
    key.extend_from_slice(LINEAR_SYNC_LINK_KEY_PREFIX);
    key.extend_from_slice(task_ref.as_bytes());
    key
}

/// The stable, domain-separated idempotency handle of one mirror operation.
///
/// Outbound callers pass `issue_updated_at_ms: None` and `event_id: None`, so
/// the id is exactly the `(task_ref, task_revision, operation_kind)` key —
/// `issue_id: None` is a create, `Some` is an update — and a retry of the same
/// logical push recomputes the same id. Inbound callers pass all three, giving
/// the full `(issue_id, issue_updated_at_ms, event_id)` key of the event being
/// applied.
///
/// The event id is load-bearing, not decoration: without it two DISTINCT
/// tracker events that share an `updated_at` mint the SAME id and the second is
/// discarded as a duplicate of the first. With it, a retry of ONE event against
/// an unchanged TASK revision still recomputes its own id, so retry idempotency
/// survives.
#[must_use]
pub fn linear_operation_id(
    direction: LinearSyncDirection,
    task_ref: EntityId,
    task_revision: u64,
    issue_id: Option<&str>,
    issue_updated_at_ms: Option<u64>,
    event_id: Option<&str>,
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(LINEAR_SYNC_OPERATION_DOMAIN);
    hasher.update(&[LINEAR_SYNC_SCHEMA_VERSION]);
    update_field(&mut hasher, Some(direction.as_str()));
    hasher.update(task_ref.as_bytes());
    hasher.update(&task_revision.to_le_bytes());
    update_field(&mut hasher, issue_id);
    match issue_updated_at_ms {
        Some(updated_at_ms) => {
            hasher.update(&[1]);
            hasher.update(&updated_at_ms.to_le_bytes());
        }
        None => {
            hasher.update(&[0]);
        }
    }
    update_field(&mut hasher, event_id);
    *hasher.finalize().as_bytes()
}

/// The durable identity of one inbound tracker event, as stored in
/// [`TaskIssueLink::seen_event_digests`].
///
/// Binds the issue, so an event id a tracker only makes unique per issue cannot
/// mask a different issue's event. Deliberately free of `updated_at`: a
/// redelivery of ONE event with a rewritten timestamp is the SAME event, and a
/// digest that moved with the clock would fail to say so.
#[must_use]
pub fn linear_event_digest(issue_id: &str, event_id: &str) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(LINEAR_SYNC_EVENT_DOMAIN);
    hasher.update(&[LINEAR_SYNC_SCHEMA_VERSION]);
    update_field(&mut hasher, Some(issue_id));
    update_field(&mut hasher, Some(event_id));
    *hasher.finalize().as_bytes()
}

/// Domain-separated, length-prefixed hash of one field value; `None` and the
/// empty string hash differently.
pub(super) fn field_hash(value: Option<&str>) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(LINEAR_SYNC_FIELD_DOMAIN);
    update_field(&mut hasher, value);
    *hasher.finalize().as_bytes()
}

/// Absorbs one optional string into a hasher with a presence byte and a length
/// prefix, so concatenations cannot collide.
fn update_field(hasher: &mut blake3::Hasher, value: Option<&str>) {
    match value {
        Some(text) => {
            hasher.update(&[1]);
            hasher.update(&(text.len() as u64).to_le_bytes());
            hasher.update(text.as_bytes());
        }
        None => {
            hasher.update(&[0]);
        }
    }
}
