use sha2::{Digest, Sha256};

use crate::batch::ENTITY_METADATA_HEADER_LEN;
use crate::batch::EntityMetadataHeader;
use crate::entity_id::{ENTITY_ID_LEN, EntityId};
use crate::error::{Error, Result};
use crate::registry::ENTITY_TYPE_CONNECTOR_KEY;
use crate::store::{GateDecisionId, GateDecisionRecord, Store};

use super::codec::{decode_connector_key_body, encode_connector_key_body};
use super::record::{ConnectorKeyRecord, ConnectorKeyStatus, validate_connector_token};

/// vault_meta connector lookup index: prefix ++ normalized connector bytes ++
/// `\0` ++ key id (16 bytes) -> `[]`.
pub(crate) const CONNECTOR_KEY_CONNECTOR_INDEX_PREFIX: &[u8] = b"connector_key/connector/v1\0";

const CONNECTOR_KEY_OP_DIFF_DOMAIN: &[u8] = b"oneiron.connector_key.op.v0";

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
