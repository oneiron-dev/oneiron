use crate::ports::EntityStoreRead;
use sha2::Digest;
use std::io::Cursor;

use rmpv::Value;
use sha2::Sha256;

use crate::entity_id::{ENTITY_ID_LEN, EntityId};
use crate::error::{Error, Result};
use crate::registry::ENTITY_TYPE_CONNECTOR_KEY;
use crate::side_table::{self, CodecError, Raw, RawValue, SideKey, SideTable};
use crate::store::{GateDecisionId, GateDecisionRecord, Store};

use super::codec::{decode_connector_key_body, encode_connector_key_body};
use super::record::{
    ConnectorKeyRecord, ConnectorKeyStatus, invalid_body, validate_connector_token,
};

/// The `(connector, key id)` pair addressed by the connector lookup index:
/// normalized connector bytes, a NUL separator, then the 16-byte id.
/// `validate_connector_token` rejects a connector containing NUL, so the
/// separator is unambiguous on decode.
pub(super) struct ConnectorIndexKey {
    pub(super) connector: String,
    pub(super) id: EntityId,
}

impl SideKey for ConnectorIndexKey {
    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self.connector.as_bytes());
        out.push(0);
        out.extend_from_slice(self.id.as_bytes());
    }

    fn decode_key(bytes: &[u8]) -> Option<Self> {
        let (rest, id_bytes) = bytes.split_at_checked(bytes.len().checked_sub(ENTITY_ID_LEN)?)?;
        let (&0, connector_bytes) = rest.split_last()? else {
            return None;
        };
        Some(Self {
            connector: String::from_utf8(connector_bytes.to_vec()).ok()?,
            id: EntityId::from_bytes(id_bytes.try_into().ok()?).ok()?,
        })
    }
}

/// vault_meta connector lookup index: normalized connector ++ `\0` ++ key id
/// -> empty marker.
pub(super) const CONNECTOR_INDEX: SideTable<ConnectorIndexKey, (), Raw> =
    SideTable::new(&side_table::CONNECTOR_KEY_CONNECTOR_INDEX);

/// vault_meta engine-catalog name index: normalized catalog name -> key id
/// (16 raw bytes).
///
/// PERMANENT by design (the ONE-1919 `SECRET_NAME_INDEX_PREFIX` shape, minus
/// its free-on-revoke behavior): [`crate::Vault::remove_connector_key`] never
/// deletes a row here, so a catalog name is unique per vault ACROSS HISTORY.
/// `describe_connector` therefore still resolves a removed connector, and a
/// name can never be recycled onto a different one.
pub(super) const CATALOG_NAME_INDEX: SideTable<String, EntityId, Raw> =
    SideTable::new(&side_table::CONNECTOR_CATALOG_NAME_INDEX);

/// vault_meta rotation-generation log: key id (16 bytes) ++ generation u32 BE
/// -> canonical msgpack `{generation, secret_ref, rotated_at}`. Point-readable
/// for `0..=key_generation`.
pub(super) const GENERATION_LOG: SideTable<(EntityId, [u8; 4]), ConnectorKeyGeneration, Raw> =
    SideTable::new(&side_table::CONNECTOR_KEY_GENERATION_LOG);

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

impl RawValue for ConnectorKeyGeneration {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, CodecError> {
        Ok(encode_connector_key_generation(self)?)
    }

    fn from_raw(bytes: &[u8]) -> std::result::Result<Self, CodecError> {
        Ok(decode_connector_key_generation(bytes)?)
    }
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
    GENERATION_LOG.get(store, txn, &(*id, generation.to_be_bytes()))
}

pub(super) fn write_connector_key_generation_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    row: &ConnectorKeyGeneration,
) -> Result<()> {
    GENERATION_LOG.put(store, wtxn, &(*id, row.generation.to_be_bytes()), row)
}

// --- Resolution ---------------------------------------------------------------

pub(super) fn read_connector_key_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<Option<ConnectorKeyRecord>> {
    let Some(raw) = store.port_entity_record(txn, id)? else {
        return Ok(None);
    };

    if raw.entity_type != ENTITY_TYPE_CONNECTOR_KEY {
        return Err(Error::InvalidEntityType(raw.entity_type));
    }
    decode_connector_key_body(&raw.body).map(Some)
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
    if validate_connector_token(connector).is_err() {
        // A blank/invalid connector token can never have a registered key.
        return Ok(None);
    }
    let mut key_prefix = connector.as_bytes().to_vec();
    key_prefix.push(0);
    let candidate_ids = CONNECTOR_INDEX
        .scan_from(store, txn, &key_prefix)?
        .into_iter()
        .map(|(key, ())| key.id)
        .collect::<Vec<_>>();

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
    crate::ports::EntityStoreMaintenance::port_connector_key_rewrite(store, wtxn, id, record)
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
            decision_id: GateDecisionId::from_bytes(store.clock.ulid()?),
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

pub(crate) fn rebuild_checkpoint_connector_index(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    id: EntityId,
    body: &[u8],
) -> Result<()> {
    let record = decode_connector_key_body(body)?;
    CONNECTOR_INDEX.put(
        store,
        txn,
        &ConnectorIndexKey {
            connector: record.connector,
            id,
        },
        &(),
    )
}
