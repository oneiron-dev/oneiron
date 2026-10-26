//! Claim-store readers and the msgpack value toolkit.

use crate::ports::EdgeStoreRead;
use crate::ports::EntityStoreRead;

use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::claim::{ClaimBody, ClaimLifecycleStatus, decode_claim_body};
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::registry::ENTITY_TYPE_CLAIM;
use crate::store::Store;

/// Live claim heads of `predicate` on `subject`.
///
/// Lifecycle is the filter; approval status deliberately is NOT. Requiring an
/// APPROVED evidence claim would put a human approval in front of every
/// compliant send — precisely the blanket review step this gate exists to
/// avoid — and it would do so on the permissive side only, which is where a
/// stall is most expensive and least protective. This matches CA-01's stated
/// posture for the enforcement-read families. Superseding or retracting a head
/// is the way to withdraw it.
pub(super) fn active_claim_bodies_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    subject: &EntityId,
    predicate: &str,
) -> Result<Vec<ClaimBody>> {
    let mut bodies = Vec::new();
    for entry in store.port_edges(
        txn,
        subject,
        crate::ports::EdgeDirection::In,
        Some(EdgeKind::ClaimOf),
        None,
    )? {
        let edge_row = entry?;
        let id = edge_row.target;
        let Some(body) = claim_body_in_txn(store, txn, &id)? else {
            continue;
        };
        if body.predicate == predicate && body.lifecycle == ClaimLifecycleStatus::Active {
            bodies.push(body);
        }
    }
    Ok(bodies)
}

/// The one live head of `predicate` on `subject`, or `None` when the substrate
/// holds no single truth.
///
/// Two live heads are as reachable here as they are for `comm.jurisdiction` —
/// an offline-minted twin, a re-import — but an evidence or message-element
/// body carries no `observed_at` to order them by, so there is no tie to
/// break. Taking a head and running would let edge-storage order decide which
/// facts the gate believes, and it would do so on the permissive side, because
/// these bodies only ever ADD evidence: the reader would sail past the very
/// wall the other head refuses to vouch for. A disagreeing pair is therefore
/// no evidence, and the strict path applies. Twins that say the same thing say
/// one thing, and hydrate.
pub(super) fn sole_active_claim_body_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    subject: &EntityId,
    predicate: &str,
) -> Result<Option<ClaimBody>> {
    let mut bodies = active_claim_bodies_in_txn(store, txn, subject, predicate)?;
    let Some(head) = bodies.pop() else {
        return Ok(None);
    };
    Ok(bodies
        .iter()
        .all(|body| body.value == head.value)
        .then_some(head))
}

pub(super) fn claim_body_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<Option<ClaimBody>> {
    let Some(raw) = store.port_entity_record(txn, id)?.map(|row| row.encode()) else {
        return Ok(None);
    };
    let Some(header) = EntityMetadataHeader::parse(&raw) else {
        return Err(Error::CorruptedIndex("campaign compliance claim header"));
    };
    if header.entity_type != ENTITY_TYPE_CLAIM {
        return Ok(None);
    }
    decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], true).map(Some)
}

// ---------------------------------------------------------------------------
// MessagePack value helpers
// ---------------------------------------------------------------------------

pub(super) fn map_entries(value: &rmpv::Value) -> &[(rmpv::Value, rmpv::Value)] {
    match value {
        rmpv::Value::Map(entries) => entries,
        _ => &[],
    }
}

fn lookup<'a>(entries: &'a [(rmpv::Value, rmpv::Value)], key: &str) -> Option<&'a rmpv::Value> {
    entries
        .iter()
        .find(|(candidate, _)| candidate.as_str() == Some(key))
        .map(|(_, value)| value)
}

pub(super) fn nested_map<'a>(
    entries: &'a [(rmpv::Value, rmpv::Value)],
    key: &str,
) -> Option<&'a [(rmpv::Value, rmpv::Value)]> {
    match lookup(entries, key)? {
        rmpv::Value::Map(nested) => Some(nested),
        _ => None,
    }
}

pub(super) fn nested_text(entries: &[(rmpv::Value, rmpv::Value)], key: &str) -> Option<String> {
    let text = lookup(entries, key)?.as_str()?.trim();
    (!text.is_empty()).then(|| text.to_owned())
}

/// The non-blank strings of the array at `key`, trimmed; anything else in it
/// is skipped, and a missing or non-array value is an empty list.
pub(super) fn nested_texts(entries: &[(rmpv::Value, rmpv::Value)], key: &str) -> Vec<String> {
    let Some(rmpv::Value::Array(items)) = lookup(entries, key) else {
        return Vec::new();
    };
    items
        .iter()
        .filter_map(rmpv::Value::as_str)
        .map(str::trim)
        .filter(|text| !text.is_empty())
        .map(str::to_owned)
        .collect()
}

pub(super) fn nested_flag(entries: &[(rmpv::Value, rmpv::Value)], key: &str) -> bool {
    lookup(entries, key).and_then(rmpv::Value::as_bool) == Some(true)
}

/// Entity references cross the CA-pack wire as CANONICAL lowercase hex — the
/// one spelling `campaign/claims.rs` established, because [`EntityId`] has no
/// serde impl. A non-canonical spelling is not a reference.
pub(super) fn nested_entity_ref(
    entries: &[(rmpv::Value, rmpv::Value)],
    key: &str,
) -> Option<EntityId> {
    let hex = lookup(entries, key)?.as_str()?;
    let id = EntityId::from_hex(hex).ok()?;
    (id.to_hex() == hex).then_some(id)
}
