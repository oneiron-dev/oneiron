//! vault_meta key codecs and msgpack rows for the follow-up cursor, wait binding and signal marker.

use rmpv::Value;

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::side_table::{self, CodecError, Raw, RawValue, SideTable};

use super::model::{
    HUMAN_TASK_FOLLOWUP_SCHEMA_VERSION, HumanFollowupStage, HumanTaskFollowupRecord,
    HumanTaskWaitBinding,
};

/// The follow-up cursor for one TASK, keyed by the task's own id.
pub(super) const FOLLOWUPS: SideTable<EntityId, HumanTaskFollowupRecord, Raw> =
    SideTable::new(&side_table::HUMAN_TASK_FOLLOWUP);

/// One C9 wait binding, keyed by the task's own id.
pub(super) const WAIT_BINDINGS: SideTable<EntityId, HumanTaskWaitBinding, Raw> =
    SideTable::new(&side_table::HUMAN_TASK_WAIT_BINDING);

/// Records which response event already produced a signal for one wait, so a
/// re-delivered response returns the first signal instead of re-driving the
/// trap state machine. Keyed by the trap claim id; value is
/// `(signal_ref, surface_event_ref)`.
pub(super) const WAIT_SIGNALS: SideTable<EntityId, (EntityId, EntityId), Raw> =
    SideTable::new(&side_table::HUMAN_TASK_WAIT_SIGNAL);

const KEY_SCHEMA_VERSION: &str = "schema_version";

const KEY_TASK_REF: &str = "task_ref";

const KEY_ASSIGNEE_REF: &str = "assignee_ref";

const KEY_STAGE: &str = "stage";

const KEY_STAGE_GENERATION: &str = "stage_generation";

const KEY_NEXT_DUE_AT: &str = "next_due_at";

const KEY_REMINDERS_SENT: &str = "reminders_sent";

const KEY_LAST_RECEIPT_REF: &str = "last_receipt_ref";

const KEY_COMPLETED_AT: &str = "completed_at";

const KEY_RESPONDER_REF: &str = "responder_ref";

const KEY_TRAP_CLAIM_ID: &str = "trap_claim_id";

const KEY_STEP_HASH: &str = "step_hash";

const KEY_IS_ACTIVE: &str = "is_active";

const KEY_SIGNAL_REF: &str = "signal_ref";

const KEY_SURFACE_EVENT_REF: &str = "surface_event_ref";

/// Synced-truth address field on a comm-owned PERSON body.
pub(super) const KEY_PARTY_KEY: &str = "party_key";

// ── storage ─────────────────────────────────────────────────────────────────

fn encoded(entries: Vec<(Value, Value)>) -> Vec<u8> {
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, &Value::Map(entries))
        .expect("writing msgpack into a Vec is infallible");
    bytes
}

fn entity_value(id: EntityId) -> Value {
    Value::Binary(id.as_bytes().to_vec())
}

fn optional_u64_value(value: Option<u64>) -> Value {
    value.map_or(Value::Nil, Value::from)
}

fn optional_str_value(value: Option<&str>) -> Value {
    value.map_or(Value::Nil, Value::from)
}

fn field<'v>(entries: &'v [(Value, Value)], key: &str) -> Option<&'v Value> {
    entries
        .iter()
        .find_map(|(name, value)| (name.as_str() == Some(key)).then_some(value))
}

fn decode_map(raw: &[u8], what: &'static str) -> Result<Vec<(Value, Value)>> {
    let value = rmpv::decode::read_value(&mut std::io::Cursor::new(raw))
        .map_err(|_| Error::CorruptedIndex(what))?;
    match value {
        Value::Map(entries) => Ok(entries),
        _ => Err(Error::CorruptedIndex(what)),
    }
}

fn decode_entity(entries: &[(Value, Value)], key: &str, what: &'static str) -> Result<EntityId> {
    let Some(Value::Binary(bytes)) = field(entries, key) else {
        return Err(Error::CorruptedIndex(what));
    };
    let bytes: [u8; 16] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| Error::CorruptedIndex(what))?;
    EntityId::from_bytes(bytes).map_err(|_| Error::CorruptedIndex(what))
}

fn decode_u64(entries: &[(Value, Value)], key: &str, what: &'static str) -> Result<u64> {
    field(entries, key)
        .and_then(Value::as_u64)
        .ok_or(Error::CorruptedIndex(what))
}

fn followup_record_body(record: &HumanTaskFollowupRecord) -> Vec<u8> {
    encoded(vec![
        (
            Value::from(KEY_SCHEMA_VERSION),
            Value::from(record.schema_version),
        ),
        (Value::from(KEY_TASK_REF), entity_value(record.task_ref)),
        (
            Value::from(KEY_ASSIGNEE_REF),
            entity_value(record.assignee_ref),
        ),
        (Value::from(KEY_STAGE), Value::from(record.stage.as_str())),
        (
            Value::from(KEY_STAGE_GENERATION),
            Value::from(record.stage_generation),
        ),
        (
            Value::from(KEY_NEXT_DUE_AT),
            optional_u64_value(record.next_due_at),
        ),
        (
            Value::from(KEY_REMINDERS_SENT),
            Value::from(record.reminders_sent),
        ),
        (
            Value::from(KEY_LAST_RECEIPT_REF),
            optional_str_value(record.last_receipt_ref.as_deref()),
        ),
        (
            Value::from(KEY_COMPLETED_AT),
            optional_u64_value(record.completed_at),
        ),
    ])
}

impl RawValue for HumanTaskFollowupRecord {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, CodecError> {
        Ok(followup_record_body(self))
    }

    fn from_raw(bytes: &[u8]) -> std::result::Result<Self, CodecError> {
        Ok(decode_followup_record(bytes)?)
    }
}

pub(super) fn put_followup_record_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    record: &HumanTaskFollowupRecord,
) -> Result<()> {
    FOLLOWUPS.put(&vault.store, wtxn, &record.task_ref, record)?;
    Ok(())
}

pub(super) fn followup_record_in_txn(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    task_ref: EntityId,
) -> Result<Option<HumanTaskFollowupRecord>> {
    FOLLOWUPS.get(&vault.store, rtxn, &task_ref)
}

fn decode_followup_record(raw: &[u8]) -> Result<HumanTaskFollowupRecord> {
    const WHAT: &str = "human_task.followup row";
    let entries = decode_map(raw, WHAT)?;
    let schema_version = u8::try_from(decode_u64(&entries, KEY_SCHEMA_VERSION, WHAT)?)
        .map_err(|_| Error::CorruptedIndex(WHAT))?;
    if schema_version != HUMAN_TASK_FOLLOWUP_SCHEMA_VERSION {
        return Err(Error::CorruptedIndex(WHAT));
    }
    let stage = field(&entries, KEY_STAGE)
        .and_then(Value::as_str)
        .ok_or(Error::CorruptedIndex(WHAT))
        .and_then(HumanFollowupStage::from_token)?;
    Ok(HumanTaskFollowupRecord {
        schema_version,
        task_ref: decode_entity(&entries, KEY_TASK_REF, WHAT)?,
        assignee_ref: decode_entity(&entries, KEY_ASSIGNEE_REF, WHAT)?,
        stage,
        stage_generation: u32::try_from(decode_u64(&entries, KEY_STAGE_GENERATION, WHAT)?)
            .map_err(|_| Error::CorruptedIndex(WHAT))?,
        next_due_at: field(&entries, KEY_NEXT_DUE_AT).and_then(Value::as_u64),
        reminders_sent: u32::try_from(decode_u64(&entries, KEY_REMINDERS_SENT, WHAT)?)
            .map_err(|_| Error::CorruptedIndex(WHAT))?,
        last_receipt_ref: field(&entries, KEY_LAST_RECEIPT_REF)
            .and_then(Value::as_str)
            .map(str::to_owned),
        completed_at: field(&entries, KEY_COMPLETED_AT).and_then(Value::as_u64),
    })
}

fn wait_binding_body(binding: &HumanTaskWaitBinding) -> Vec<u8> {
    encoded(vec![
        (Value::from(KEY_TASK_REF), entity_value(binding.task_ref)),
        (
            Value::from(KEY_RESPONDER_REF),
            entity_value(binding.responder_ref),
        ),
        (
            Value::from(KEY_TRAP_CLAIM_ID),
            entity_value(binding.trap_claim_id),
        ),
        (
            Value::from(KEY_STEP_HASH),
            Value::Binary(binding.step_hash.to_vec()),
        ),
        (Value::from(KEY_IS_ACTIVE), Value::from(binding.is_active)),
    ])
}

impl RawValue for HumanTaskWaitBinding {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, CodecError> {
        Ok(wait_binding_body(self))
    }

    fn from_raw(bytes: &[u8]) -> std::result::Result<Self, CodecError> {
        Ok(decode_wait_binding(bytes)?)
    }
}

pub(super) fn put_wait_binding_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    binding: &HumanTaskWaitBinding,
) -> Result<()> {
    WAIT_BINDINGS.put(&vault.store, wtxn, &binding.task_ref, binding)?;
    Ok(())
}

fn decode_wait_binding(raw: &[u8]) -> Result<HumanTaskWaitBinding> {
    const WHAT: &str = "human_task.wait row";
    let entries = decode_map(raw, WHAT)?;
    let Some(Value::Binary(step_hash)) = field(&entries, KEY_STEP_HASH) else {
        return Err(Error::CorruptedIndex(WHAT));
    };
    let step_hash: [u8; 32] = step_hash
        .as_slice()
        .try_into()
        .map_err(|_| Error::CorruptedIndex(WHAT))?;
    let Some(Value::Boolean(is_active)) = field(&entries, KEY_IS_ACTIVE) else {
        return Err(Error::CorruptedIndex(WHAT));
    };
    Ok(HumanTaskWaitBinding {
        task_ref: decode_entity(&entries, KEY_TASK_REF, WHAT)?,
        responder_ref: decode_entity(&entries, KEY_RESPONDER_REF, WHAT)?,
        trap_claim_id: decode_entity(&entries, KEY_TRAP_CLAIM_ID, WHAT)?,
        step_hash,
        is_active: *is_active,
    })
}

fn wait_signal_body(signal_ref: EntityId, surface_event_ref: EntityId) -> Vec<u8> {
    encoded(vec![
        (Value::from(KEY_SIGNAL_REF), entity_value(signal_ref)),
        (
            Value::from(KEY_SURFACE_EVENT_REF),
            entity_value(surface_event_ref),
        ),
    ])
}

fn decode_wait_signal(raw: &[u8]) -> Result<(EntityId, EntityId)> {
    const WHAT: &str = "human_task.wait.signal row";
    let entries = decode_map(raw, WHAT)?;
    Ok((
        decode_entity(&entries, KEY_SIGNAL_REF, WHAT)?,
        decode_entity(&entries, KEY_SURFACE_EVENT_REF, WHAT)?,
    ))
}

impl RawValue for (EntityId, EntityId) {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, CodecError> {
        Ok(wait_signal_body(self.0, self.1))
    }

    fn from_raw(bytes: &[u8]) -> std::result::Result<Self, CodecError> {
        Ok(decode_wait_signal(bytes)?)
    }
}

pub(super) fn put_wait_signal_marker_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    trap_claim_id: EntityId,
    signal_ref: EntityId,
    surface_event_ref: EntityId,
) -> Result<()> {
    WAIT_SIGNALS.put(
        &vault.store,
        wtxn,
        &trap_claim_id,
        &(signal_ref, surface_event_ref),
    )?;
    Ok(())
}

pub(super) fn wait_signal_marker(
    vault: &Vault,
    trap_claim_id: EntityId,
) -> Result<Option<(EntityId, EntityId)>> {
    let rtxn = vault.store.env.read_txn()?;
    WAIT_SIGNALS.get(&vault.store, &rtxn, &trap_claim_id)
}
