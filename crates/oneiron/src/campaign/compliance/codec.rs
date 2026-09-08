//! Claim-store readers, comm-party mirror, and the msgpack value toolkit.

use sha2::{Digest, Sha256};

use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::claim::{ClaimBody, ClaimLifecycleStatus, decode_claim_body};
use crate::edge::EdgeKind;
use crate::entity_id::{ENTITY_ID_LEN, EntityId};
use crate::error::{Error, Result};
use crate::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_PERSON};
use crate::store::Store;
use crate::vault::{edge_kind_prefix, parse_edge_record};

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
    for entry in store
        .edges_in
        .prefix_iter(txn, &edge_kind_prefix(subject, EdgeKind::ClaimOf))?
    {
        let (key, value) = entry?;
        let id = parse_edge_record(&key, &value)?.target;
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
    let Some(raw) = store.entities.get(txn, id.as_bytes())? else {
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

/// Node-local party shortcut owned by `comm.rs`, re-validated against synced
/// truth. Read-only mirror; CA never writes this index.
const COMM_PARTY_INDEX_PREFIX: &[u8] = b"comm.party.v1:";

/// Synced-truth field naming a comm-owned PERSON's party.
const COMM_PARTY_KEY_FIELD: &str = "party_key";

/// Resolves the PERSON behind an external-effect `counterparty` address.
///
/// A stale shortcut resolves to NOTHING rather than to the wrong person: the
/// row must still be a PERSON carrying exactly this `party_key`. Answering
/// `None` withdraws compliance from the effect, which is why the re-validation
/// is not optional — it is the difference between "not a campaign send" and
/// "someone else's compliance facts".
pub(super) fn resolve_comm_party_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    counterparty: &str,
) -> Result<Option<EntityId>> {
    let party_key = counterparty.trim();
    if party_key.is_empty() {
        return Ok(None);
    }
    let mut key = Vec::with_capacity(COMM_PARTY_INDEX_PREFIX.len() + 32);
    key.extend_from_slice(COMM_PARTY_INDEX_PREFIX);
    key.extend_from_slice(&Sha256::digest(party_key.as_bytes()));
    let Some(raw_id) = store.vault_meta.get(txn, &key)? else {
        return Ok(None);
    };
    let Ok(bytes) = <[u8; ENTITY_ID_LEN]>::try_from(raw_id.as_ref()) else {
        return Ok(None);
    };
    let Ok(id) = EntityId::from_bytes(bytes) else {
        return Ok(None);
    };
    Ok(person_with_party_key_in_txn(store, txn, &id, party_key)?.then_some(id))
}

fn person_with_party_key_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    party_key: &str,
) -> Result<bool> {
    let Some(raw) = store.entities.get(txn, id.as_bytes())? else {
        return Ok(false);
    };
    let Some(header) = EntityMetadataHeader::parse(&raw) else {
        return Ok(false);
    };
    if header.entity_type != ENTITY_TYPE_PERSON {
        return Ok(false);
    }
    let mut cursor = std::io::Cursor::new(&raw[ENTITY_METADATA_HEADER_LEN..]);
    let Ok(body) = rmpv::decode::read_value(&mut cursor) else {
        return Ok(false);
    };
    Ok(map_entries(&body).iter().any(|(key, value)| {
        key.as_str() == Some(COMM_PARTY_KEY_FIELD) && value.as_str() == Some(party_key)
    }))
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
