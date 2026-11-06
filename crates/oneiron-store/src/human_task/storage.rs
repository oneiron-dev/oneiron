//! vault_meta key codecs and msgpack rows for the follow-up cursor, wait binding and signal marker.

use rmpv::Value;

use crate::side_table::codec::CodecError;
use crate::side_table::codec::RawValue;
use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;

use oneiron_base::human_task_followup::HUMAN_TASK_FOLLOWUP_SCHEMA_VERSION;
use oneiron_base::human_task_followup::HumanFollowupStage;
use oneiron_base::human_task_followup::HumanTaskFollowupRecord;
use oneiron_base::human_task_followup::HumanTaskWaitBinding;

pub const KEY_SCHEMA_VERSION: &str = "schema_version";

pub const KEY_TASK_REF: &str = "task_ref";

pub const KEY_ASSIGNEE_REF: &str = "assignee_ref";

pub const KEY_STAGE: &str = "stage";

pub const KEY_STAGE_GENERATION: &str = "stage_generation";

pub const KEY_NEXT_DUE_AT: &str = "next_due_at";

pub const KEY_REMINDERS_SENT: &str = "reminders_sent";

pub const KEY_LAST_RECEIPT_REF: &str = "last_receipt_ref";

pub const KEY_COMPLETED_AT: &str = "completed_at";

pub const KEY_RESPONDER_REF: &str = "responder_ref";

pub const KEY_TRAP_CLAIM_ID: &str = "trap_claim_id";

pub const KEY_STEP_HASH: &str = "step_hash";

pub const KEY_IS_ACTIVE: &str = "is_active";

pub const KEY_SIGNAL_REF: &str = "signal_ref";

pub const KEY_SURFACE_EVENT_REF: &str = "surface_event_ref";

// ── storage ─────────────────────────────────────────────────────────────────

pub fn encoded(entries: Vec<(Value, Value)>) -> Vec<u8> {
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, &Value::Map(entries))
        .expect("writing msgpack into a Vec is infallible");
    bytes
}

pub fn entity_value(id: EntityId) -> Value {
    Value::Binary(id.as_bytes().to_vec())
}

pub fn optional_u64_value(value: Option<u64>) -> Value {
    value.map_or(Value::Nil, Value::from)
}

pub fn optional_str_value(value: Option<&str>) -> Value {
    value.map_or(Value::Nil, Value::from)
}

pub fn field<'v>(entries: &'v [(Value, Value)], key: &str) -> Option<&'v Value> {
    entries
        .iter()
        .find_map(|(name, value)| (name.as_str() == Some(key)).then_some(value))
}

pub fn decode_map(raw: &[u8], what: &'static str) -> Result<Vec<(Value, Value)>> {
    let value = rmpv::decode::read_value(&mut std::io::Cursor::new(raw))
        .map_err(|_| Error::CorruptedIndex(what))?;
    match value {
        Value::Map(entries) => Ok(entries),
        _ => Err(Error::CorruptedIndex(what)),
    }
}

pub fn decode_entity(
    entries: &[(Value, Value)],
    key: &str,
    what: &'static str,
) -> Result<EntityId> {
    let Some(Value::Binary(bytes)) = field(entries, key) else {
        return Err(Error::CorruptedIndex(what));
    };
    let bytes: [u8; 16] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| Error::CorruptedIndex(what))?;
    EntityId::from_bytes(bytes).map_err(|_| Error::CorruptedIndex(what))
}

pub fn decode_u64(entries: &[(Value, Value)], key: &str, what: &'static str) -> Result<u64> {
    field(entries, key)
        .and_then(Value::as_u64)
        .ok_or(Error::CorruptedIndex(what))
}

pub fn followup_record_body(record: &HumanTaskFollowupRecord) -> Vec<u8> {
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

pub fn decode_followup_record(raw: &[u8]) -> Result<HumanTaskFollowupRecord> {
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

pub fn wait_binding_body(binding: &HumanTaskWaitBinding) -> Vec<u8> {
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

pub fn decode_wait_binding(raw: &[u8]) -> Result<HumanTaskWaitBinding> {
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

pub fn wait_signal_body(signal_ref: EntityId, surface_event_ref: EntityId) -> Vec<u8> {
    encoded(vec![
        (Value::from(KEY_SIGNAL_REF), entity_value(signal_ref)),
        (
            Value::from(KEY_SURFACE_EVENT_REF),
            entity_value(surface_event_ref),
        ),
    ])
}

pub fn decode_wait_signal(raw: &[u8]) -> Result<(EntityId, EntityId)> {
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
