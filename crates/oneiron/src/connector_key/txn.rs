use std::io::Cursor;

use rmpv::Value;
use sha2::{Digest, Sha256};

use crate::batch::ENTITY_METADATA_HEADER_LEN;
use crate::batch::EntityMetadataHeader;
use crate::entity_id::{ENTITY_ID_LEN, EntityId};
use crate::error::{Error, Result};
use crate::registry::ENTITY_TYPE_CONNECTOR_KEY;
use crate::store::{GateDecisionId, GateDecisionRecord, Store};

use super::codec::{decode_connector_key_body, encode_connector_key_body};
use super::record::{
    ConnectorKeyRecord, ConnectorKeyStatus, invalid_body, validate_connector_token,
};

/// vault_meta connector lookup index: prefix ++ normalized connector bytes ++
/// `\0` ++ key id (16 bytes) -> `[]`.
pub(crate) const CONNECTOR_KEY_CONNECTOR_INDEX_PREFIX: &[u8] = b"connector_key/connector/v1\0";

/// vault_meta engine-catalog name index: prefix ++ normalized catalog name ->
/// key id (16 bytes).
///
/// PERMANENT by design (the ONE-1919 `SECRET_NAME_INDEX_PREFIX` shape, minus
/// its free-on-revoke behavior): [`crate::Vault::remove_connector_key`] never
/// deletes a row here, so a catalog name is unique per vault ACROSS HISTORY.
/// `describe_connector` therefore still resolves a removed connector, and a
/// name can never be recycled onto a different one.
pub const CONNECTOR_CATALOG_NAME_INDEX_PREFIX: &[u8] = b"connector_catalog/name/v1\0";

/// vault_meta rotation-generation log: prefix ++ key id (16 bytes) ++
/// generation u32 BE -> canonical msgpack `{generation, secret_ref,
/// rotated_at}`. Point-readable for `0..=key_generation`.
pub const CONNECTOR_KEY_GENERATION_LOG_PREFIX: &[u8] = b"connector_key/generation/v1\0";

const CONNECTOR_KEY_OP_DIFF_DOMAIN: &[u8] = b"oneiron.connector_key.op.v0";

const GENERATION_LOG_KEYS: [&str; 3] = ["generation", "secret_ref", "rotated_at"];

/// One entry of a connector key's rotation-generation log: which custody
/// record the key pointed at while that generation was current.
///
/// Value-less like the record itself — `secret_ref` is a custody NAME.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectorKeyGeneration {
    pub generation: u32,
    /// The custody record NAME this generation pointed at; `None` for a key
    /// that had no custody reference at that generation.
    pub secret_ref: Option<String>,
    /// `registered_at` for generation 0 (including a lazily backfilled one),
    /// the rotation stamp for every later generation.
    pub rotated_at: u64,
}

// --- vault_meta keys ---------------------------------------------------------

pub(crate) fn connector_key_index_prefix(connector: &str) -> Result<Vec<u8>> {
    validate_connector_token(connector)?;
    let mut key = Vec::with_capacity(
        CONNECTOR_KEY_CONNECTOR_INDEX_PREFIX.len() + connector.len() + 1 + ENTITY_ID_LEN,
    );
    key.extend_from_slice(CONNECTOR_KEY_CONNECTOR_INDEX_PREFIX);
    key.extend_from_slice(connector.as_bytes());
    key.push(0);
    Ok(key)
}

pub(crate) fn connector_key_index_key(connector: &str, id: &EntityId) -> Result<Vec<u8>> {
    let mut key = connector_key_index_prefix(connector)?;
    key.extend_from_slice(id.as_bytes());
    Ok(key)
}

pub(crate) fn connector_key_index_entity_id(key: &[u8], connector: &str) -> Result<EntityId> {
    let prefix = connector_key_index_prefix(connector)?;
    if key.len() != prefix.len() + ENTITY_ID_LEN || !key.starts_with(&prefix) {
        return Err(Error::CorruptedIndex("connector key connector index key"));
    }
    let mut raw_id = [0; ENTITY_ID_LEN];
    raw_id.copy_from_slice(&key[prefix.len()..]);
    EntityId::from_bytes(raw_id)
        .map_err(|_| Error::CorruptedIndex("connector key connector index key"))
}

/// The permanent name-index key for one normalized catalog name.
pub(super) fn connector_catalog_name_index_key(name: &str) -> Vec<u8> {
    let mut key = Vec::with_capacity(CONNECTOR_CATALOG_NAME_INDEX_PREFIX.len() + name.len());
    key.extend_from_slice(CONNECTOR_CATALOG_NAME_INDEX_PREFIX);
    key.extend_from_slice(name.as_bytes());
    key
}

/// Reads the key id out of a catalog name-index VALUE (raw identity bytes —
/// the index never stores the public hex form).
pub(super) fn connector_catalog_index_entity_id(value: &[u8]) -> Result<EntityId> {
    let raw: [u8; ENTITY_ID_LEN] = value
        .try_into()
        .map_err(|_| Error::CorruptedIndex("connector catalog name index id"))?;
    EntityId::from_bytes(raw).map_err(|_| Error::CorruptedIndex("connector catalog name index id"))
}

/// The generation-log key for one `(key id, generation)` pair. Big-endian so
/// a prefix scan walks generations in ascending order.
pub(super) fn connector_key_generation_key(id: &EntityId, generation: u32) -> Vec<u8> {
    let mut key = Vec::with_capacity(
        CONNECTOR_KEY_GENERATION_LOG_PREFIX.len() + ENTITY_ID_LEN + size_of::<u32>(),
    );
    key.extend_from_slice(CONNECTOR_KEY_GENERATION_LOG_PREFIX);
    key.extend_from_slice(id.as_bytes());
    key.extend_from_slice(&generation.to_be_bytes());
    key
}

fn encode_connector_key_generation(row: &ConnectorKeyGeneration) -> Result<Vec<u8>> {
    let value = Value::Map(vec![
        (
            Value::from(GENERATION_LOG_KEYS[0]),
            Value::from(u64::from(row.generation)),
        ),
        (
            Value::from(GENERATION_LOG_KEYS[1]),
            row.secret_ref.as_deref().map_or(Value::Nil, Value::from),
        ),
        (
            Value::from(GENERATION_LOG_KEYS[2]),
            Value::from(row.rotated_at),
        ),
    ]);
    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, &value).map_err(|_| {
        Error::InvariantViolation("connector key generation MessagePack encode failed")
    })?;
    Ok(out)
}

fn decode_connector_key_generation(bytes: &[u8]) -> Result<ConnectorKeyGeneration> {
    let mut cursor = Cursor::new(bytes);
    let value = rmpv::decode::read_value(&mut cursor)
        .map_err(|_| Error::CorruptedIndex("connector key generation row"))?;
    let Value::Map(entries) = &value else {
        return Err(Error::CorruptedIndex("connector key generation row"));
    };
    let field = |key: &str| {
        entries
            .iter()
            .find_map(|(candidate, value)| (candidate.as_str() == Some(key)).then_some(value))
            .ok_or(Error::CorruptedIndex("connector key generation row"))
    };
    let generation = field(GENERATION_LOG_KEYS[0])?
        .as_u64()
        .and_then(|raw| u32::try_from(raw).ok())
        .ok_or(Error::CorruptedIndex("connector key generation row"))?;
    let secret_ref = match field(GENERATION_LOG_KEYS[1])? {
        Value::Nil => None,
        value => Some(
            value
                .as_str()
                .ok_or(Error::CorruptedIndex("connector key generation row"))?
                .to_owned(),
        ),
    };
    Ok(ConnectorKeyGeneration {
        generation,
        secret_ref,
        rotated_at: field(GENERATION_LOG_KEYS[2])?
            .as_u64()
            .ok_or(Error::CorruptedIndex("connector key generation row"))?,
    })
}

pub(super) fn read_connector_key_generation_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    generation: u32,
) -> Result<Option<ConnectorKeyGeneration>> {
    let Some(bytes) = store
        .vault_meta
        .get(txn, &connector_key_generation_key(id, generation))?
    else {
        return Ok(None);
    };
    decode_connector_key_generation(&bytes).map(Some)
}

pub(super) fn write_connector_key_generation_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    row: &ConnectorKeyGeneration,
) -> Result<()> {
    let encoded = encode_connector_key_generation(row)?;
    store.vault_meta.put(
        wtxn,
        &connector_key_generation_key(id, row.generation),
        &encoded,
    )?;
    Ok(())
}

// --- Resolution ---------------------------------------------------------------

pub(super) fn read_connector_key_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<Option<ConnectorKeyRecord>> {
    let Some(raw) = store.entities.get(txn, id.as_bytes())? else {
        return Ok(None);
    };
    let header = EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
    if header.entity_type != ENTITY_TYPE_CONNECTOR_KEY {
        return Err(Error::InvalidEntityType(header.entity_type));
    }
    decode_connector_key_body(&raw[ENTITY_METADATA_HEADER_LEN..]).map(Some)
}

/// Resolves the connector key governing one effect: within a `(connector,
/// actor_entity_ref)` tuple the non-revoked record wins; the exact actor
/// tuple wins over the actor-agnostic tuple; a revoked-only tuple still
/// resolves (the status wall reports `connector_key_revoked` instead of
/// silently un-governing the connector). `connector` must be normalized.
pub(crate) fn governing_connector_key(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    connector: &str,
    actor_entity_ref: Option<&EntityId>,
) -> Result<Option<(EntityId, ConnectorKeyRecord)>> {
    let Ok(prefix) = connector_key_index_prefix(connector) else {
        // A blank/invalid connector token can never have a registered key.
        return Ok(None);
    };
    let mut candidate_ids = Vec::new();
    for entry in store.vault_meta.prefix_iter(txn, &prefix)? {
        let (key, _) = entry?;
        candidate_ids.push(connector_key_index_entity_id(&key, connector)?);
    }

    let mut exact: Vec<(EntityId, ConnectorKeyRecord)> = Vec::new();
    let mut agnostic: Vec<(EntityId, ConnectorKeyRecord)> = Vec::new();
    for id in candidate_ids {
        let record = read_connector_key_in_txn(store, txn, &id)?
            .ok_or(Error::CorruptedIndex("connector key index row"))?;
        match (record.actor_entity_ref.as_ref(), actor_entity_ref) {
            (Some(bound), Some(actor)) if bound == actor => exact.push((id, record)),
            (None, _) => agnostic.push((id, record)),
            _ => {}
        }
    }

    let pick = |hits: Vec<(EntityId, ConnectorKeyRecord)>| {
        let mut revoked_only = None;
        for hit in hits {
            if hit.1.status != ConnectorKeyStatus::Revoked {
                return Some(hit);
            }
            if revoked_only.is_none() {
                revoked_only = Some(hit);
            }
        }
        revoked_only
    };
    if let Some(hit) = pick(exact) {
        return Ok(Some(hit));
    }
    Ok(pick(agnostic))
}

// --- In-txn rewrites -----------------------------------------------------------

/// Rewrites a connector-key entity body in place, preserving the entity
/// header (the `touch_standing_outbound_grant_in_txn` pattern — the connector
/// never changes, so the connector index needs no maintenance).
pub(crate) fn rewrite_connector_key_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    record: &ConnectorKeyRecord,
) -> Result<()> {
    let Some(raw) = store.entities.get(wtxn, id.as_bytes())? else {
        return Err(Error::EntityNotFound);
    };
    let header = EntityMetadataHeader::parse(&raw)
        .ok_or(Error::CorruptedIndex("connector key entity header"))?;
    if header.entity_type != ENTITY_TYPE_CONNECTOR_KEY {
        return Err(Error::CorruptedIndex("connector key entity type"));
    }
    let body = encode_connector_key_body(record)?;
    let mut payload = Vec::with_capacity(ENTITY_METADATA_HEADER_LEN + body.len());
    payload.push(ENTITY_TYPE_CONNECTOR_KEY);
    payload.extend_from_slice(&header.occurred_start.to_be_bytes());
    payload.extend_from_slice(&header.occurred_end.to_be_bytes());
    payload.extend_from_slice(&header.learned_at.to_be_bytes());
    payload.extend_from_slice(&body);
    store.entities.put(wtxn, id.as_bytes(), &payload)?;
    Ok(())
}

/// The receipt-free terminal-revocation core, extracted so the two doors that
/// need it can each stamp their OWN receipt: `Vault::revoke_connector_key`
/// appends `gate.connector_key.revoke`, `Vault::remove_connector_key` appends
/// EXACTLY ONE `gate.connector_key.remove` and never a revoke record. The
/// caller owns the status-transition check.
///
/// Revocation is terminal, so any staged (unapproved) charter and every
/// advisory budget suggestion drop here: a revoked key carries no mutable
/// state. The `catalog` entry deliberately SURVIVES — removal is catalog
/// HISTORY, not catalog erasure.
pub(super) fn revoke_connector_key_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    record: &ConnectorKeyRecord,
    at: u64,
) -> Result<ConnectorKeyRecord> {
    let revoked = ConnectorKeyRecord {
        status: ConnectorKeyStatus::Revoked,
        status_changed_at: Some(at),
        suspended_reason: None,
        pending_charter: None,
        suggested_budgets: Vec::new(),
        ..record.clone()
    };
    rewrite_connector_key_in_txn(store, wtxn, id, &revoked)?;
    Ok(revoked)
}

/// Rejects a lifecycle op on an already-terminal key with the module's one
/// illegal-transition error, so `remove` on a Revoked key reports exactly what
/// `revoke` on a Revoked key reports.
pub(super) fn reject_terminal_transition() -> Error {
    invalid_body("illegal status transition")
}

/// Flips a key to Suspended inside the caller's transaction (used by the gate
/// on exhaust-suspend and by `Vault::suspend_connector_key`).
pub(crate) fn suspend_connector_key_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    record: &ConnectorKeyRecord,
    reason: String,
    at: u64,
) -> Result<ConnectorKeyRecord> {
    let suspended = ConnectorKeyRecord {
        status: ConnectorKeyStatus::Suspended,
        status_changed_at: Some(at),
        suspended_reason: Some(reason),
        ..record.clone()
    };
    rewrite_connector_key_in_txn(store, wtxn, id, &suspended)?;
    Ok(suspended)
}

// --- Receipted lifecycle ops -----------------------------------------------------

pub(super) fn append_connector_key_op_record(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    op_reason: &'static str,
    record: &ConnectorKeyRecord,
    policy_frontier: [u8; 32],
    at: u64,
) -> Result<()> {
    let body = encode_connector_key_body(record)?;
    let mut hasher = Sha256::new();
    hasher.update(CONNECTOR_KEY_OP_DIFF_DOMAIN);
    hasher.update(&body);
    store.append_gate_decision_in_txn(
        wtxn,
        &GateDecisionRecord {
            version: 0,
            decision_id: GateDecisionId::now(),
            created_at: at,
            outcome: "allow".to_owned(),
            reason_codes: vec![op_reason.to_owned()],
            receipt_reasons: Vec::new(),
            system_notices: Vec::new(),
            actor_class: "first_party".to_owned(),
            actor_ref: None,
            content_kind: "connector_key_op".to_owned(),
            policy_manifest_version: crate::gate::POLICY_SCHEMA_VERSION.to_owned(),
            claim_id: None,
            grant_ref: Some(format!("ckey:{}", id.to_hex())),
            diff_handle: hasher.finalize().to_vec(),
            read_frontier_hash: policy_frontier,
            redacted_at: None,
        },
    )
}
