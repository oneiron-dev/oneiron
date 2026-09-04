use std::io::Cursor;

use rmpv::Value;

use crate::entity_id::{ENTITY_ID_LEN, EntityId};
use crate::error::{Error, Result};

use super::record::{
    CalendarPeriod, CompiledConnectorPolicy, ConnectorCallClass, ConnectorCatalogEntry,
    ConnectorCharterBlock, ConnectorKeyRecord, ConnectorKeyStatus, EffectorBudget,
    EffectorBudgetDimension, EffectorBudgetOnExhaust, EffectorBudgetReservePolicy,
    EffectorBudgetWindow, PendingConnectorCharter, invalid_body,
};

/// Current ConnectorKeyRecord body schema version.
///
/// v3 (ONE-1886) appends `secret_ref` / `key_generation` / `catalog` as
/// OPTIONAL keys. The append is purely additive: positions 0-10 below never
/// move, decode still accepts every prior version, and a stored v1/v2 body
/// reads back as `secret_ref = None`, `key_generation = 0`, `catalog = None`
/// — re-encoding to v3 only on the row's next natural write, never as a bulk
/// migration.
pub const CONNECTOR_KEY_SCHEMA_VERSION: u64 = 3;

/// Pinned on-disk MessagePack key set for ConnectorKeyRecord bodies.
///
/// APPEND-ONLY and position-addressed by the `KEY_*` consts below: an existing
/// index must never move, or every stored body silently re-reads as a
/// different field.
pub const CONNECTOR_KEY_BODY_KEYS: [&str; 14] = [
    "schema_version",
    "connector",
    "actor_entity_ref",
    "status",
    "budgets",
    "registered_at",
    "status_changed_at",
    "suspended_reason",
    "charter",
    "pending_charter",
    "suggested_budgets",
    "secret_ref",
    "key_generation",
    "catalog",
];

const KEY_SCHEMA_VERSION: &str = CONNECTOR_KEY_BODY_KEYS[0];
const KEY_CONNECTOR: &str = CONNECTOR_KEY_BODY_KEYS[1];
const KEY_ACTOR_ENTITY_REF: &str = CONNECTOR_KEY_BODY_KEYS[2];
const KEY_STATUS: &str = CONNECTOR_KEY_BODY_KEYS[3];
const KEY_BUDGETS: &str = CONNECTOR_KEY_BODY_KEYS[4];
const KEY_REGISTERED_AT: &str = CONNECTOR_KEY_BODY_KEYS[5];
const KEY_STATUS_CHANGED_AT: &str = CONNECTOR_KEY_BODY_KEYS[6];
const KEY_SUSPENDED_REASON: &str = CONNECTOR_KEY_BODY_KEYS[7];
const KEY_CHARTER: &str = CONNECTOR_KEY_BODY_KEYS[8];
const KEY_PENDING_CHARTER: &str = CONNECTOR_KEY_BODY_KEYS[9];
const KEY_SUGGESTED_BUDGETS: &str = CONNECTOR_KEY_BODY_KEYS[10];
const KEY_SECRET_REF: &str = CONNECTOR_KEY_BODY_KEYS[11];
const KEY_KEY_GENERATION: &str = CONNECTOR_KEY_BODY_KEYS[12];
const KEY_CATALOG: &str = CONNECTOR_KEY_BODY_KEYS[13];
const OPTIONAL_CONNECTOR_KEY_BODY_KEYS: [&str; 4] = [
    KEY_SUGGESTED_BUDGETS,
    KEY_SECRET_REF,
    KEY_KEY_GENERATION,
    KEY_CATALOG,
];

const CATALOG_ENTRY_KEYS: [&str; 6] = [
    "name",
    "connector",
    "summary",
    "verbs",
    "call_class",
    "registered_at",
];

const BUDGET_KEYS: [&str; 7] = [
    "dimension",
    "channel_class",
    "limit",
    "unit",
    "window",
    "on_exhaust",
    "reserve_policy",
];
const ROLLING_WINDOW_KEYS: [&str; 2] = ["kind", "duration_s"];
const CALENDAR_WINDOW_KEYS: [&str; 3] = ["kind", "period", "tz"];
const WINDOW_KIND_ROLLING: &str = "rolling";
const WINDOW_KIND_CALENDAR: &str = "calendar";

const CHARTER_BLOCK_KEYS: [&str; 7] = [
    "text",
    "text_hash",
    "compiled",
    "compiled_hash",
    "stamped_aggregate",
    "stamped_by",
    "stamped_at",
];
const PENDING_CHARTER_KEYS: [&str; 5] = [
    "text",
    "text_hash",
    "compiled",
    "compiled_hash",
    "proposed_at",
];
const COMPILED_POLICY_KEYS: [&str; 2] = ["never_list", "channel_caps"];

// --- Encoding ---------------------------------------------------------------

/// Encodes a ConnectorKeyRecord body in canonical MessagePack field order.
pub fn encode_connector_key_body(record: &ConnectorKeyRecord) -> Result<Vec<u8>> {
    record.validate()?;
    let value = Value::Map(vec![
        (
            Value::from(KEY_SCHEMA_VERSION),
            Value::from(CONNECTOR_KEY_SCHEMA_VERSION),
        ),
        (
            Value::from(KEY_CONNECTOR),
            Value::from(record.connector.clone()),
        ),
        (
            Value::from(KEY_ACTOR_ENTITY_REF),
            record
                .actor_entity_ref
                .as_ref()
                .map_or(Value::Nil, |id| Value::Binary(id.as_bytes().to_vec())),
        ),
        (Value::from(KEY_STATUS), Value::from(record.status.as_str())),
        (
            Value::from(KEY_BUDGETS),
            Value::Array(record.budgets.iter().map(encode_budget_row).collect()),
        ),
        (
            Value::from(KEY_REGISTERED_AT),
            Value::from(record.registered_at),
        ),
        (
            Value::from(KEY_STATUS_CHANGED_AT),
            record.status_changed_at.map_or(Value::Nil, Value::from),
        ),
        (
            Value::from(KEY_SUSPENDED_REASON),
            option_string_value(record.suspended_reason.as_deref()),
        ),
        (
            Value::from(KEY_CHARTER),
            record
                .charter
                .as_ref()
                .map_or(Value::Nil, encode_charter_block),
        ),
        (
            Value::from(KEY_PENDING_CHARTER),
            record
                .pending_charter
                .as_ref()
                .map_or(Value::Nil, encode_pending_charter),
        ),
        (
            Value::from(KEY_SUGGESTED_BUDGETS),
            Value::Array(
                record
                    .suggested_budgets
                    .iter()
                    .map(encode_budget_row)
                    .collect(),
            ),
        ),
        (
            Value::from(KEY_SECRET_REF),
            option_string_value(record.secret_ref.as_deref()),
        ),
        (
            Value::from(KEY_KEY_GENERATION),
            Value::from(u64::from(record.key_generation)),
        ),
        (
            Value::from(KEY_CATALOG),
            record
                .catalog
                .as_ref()
                .map_or(Value::Nil, encode_catalog_entry),
        ),
    ]);

    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, &value)
        .map_err(|_| Error::InvariantViolation("connector key body MessagePack encode failed"))?;
    Ok(out)
}

fn encode_budget_row(budget: &EffectorBudget) -> Value {
    Value::Map(vec![
        (
            Value::from(BUDGET_KEYS[0]),
            Value::from(budget.dimension.as_str()),
        ),
        (
            Value::from(BUDGET_KEYS[1]),
            option_string_value(budget.channel_class.as_deref()),
        ),
        (Value::from(BUDGET_KEYS[2]), Value::from(budget.limit)),
        (
            Value::from(BUDGET_KEYS[3]),
            option_string_value(budget.unit.as_deref()),
        ),
        (Value::from(BUDGET_KEYS[4]), encode_window(&budget.window)),
        (
            Value::from(BUDGET_KEYS[5]),
            Value::from(budget.on_exhaust.as_str()),
        ),
        (
            Value::from(BUDGET_KEYS[6]),
            budget
                .reserve_policy
                .map_or(Value::Nil, |policy| Value::from(policy.as_str())),
        ),
    ])
}

fn encode_window(window: &EffectorBudgetWindow) -> Value {
    match window {
        EffectorBudgetWindow::Rolling { duration_s } => Value::Map(vec![
            (
                Value::from(ROLLING_WINDOW_KEYS[0]),
                Value::from(WINDOW_KIND_ROLLING),
            ),
            (
                Value::from(ROLLING_WINDOW_KEYS[1]),
                Value::from(*duration_s),
            ),
        ]),
        EffectorBudgetWindow::Calendar { period, tz } => Value::Map(vec![
            (
                Value::from(CALENDAR_WINDOW_KEYS[0]),
                Value::from(WINDOW_KIND_CALENDAR),
            ),
            (
                Value::from(CALENDAR_WINDOW_KEYS[1]),
                Value::from(period.as_str()),
            ),
            (
                Value::from(CALENDAR_WINDOW_KEYS[2]),
                option_string_value(tz.as_deref()),
            ),
        ]),
    }
}

pub(super) fn encode_compiled_policy(compiled: &CompiledConnectorPolicy) -> Value {
    Value::Map(vec![
        (
            Value::from(COMPILED_POLICY_KEYS[0]),
            Value::Array(
                compiled
                    .never_list
                    .iter()
                    .map(|entry| Value::from(entry.clone()))
                    .collect(),
            ),
        ),
        (
            Value::from(COMPILED_POLICY_KEYS[1]),
            Value::Array(
                compiled
                    .channel_caps
                    .iter()
                    .map(encode_budget_row)
                    .collect(),
            ),
        ),
    ])
}

fn encode_charter_block(charter: &ConnectorCharterBlock) -> Value {
    Value::Map(vec![
        (
            Value::from(CHARTER_BLOCK_KEYS[0]),
            Value::from(charter.text.clone()),
        ),
        (
            Value::from(CHARTER_BLOCK_KEYS[1]),
            Value::Binary(charter.text_hash.to_vec()),
        ),
        (
            Value::from(CHARTER_BLOCK_KEYS[2]),
            encode_compiled_policy(&charter.compiled),
        ),
        (
            Value::from(CHARTER_BLOCK_KEYS[3]),
            Value::Binary(charter.compiled_hash.to_vec()),
        ),
        (
            Value::from(CHARTER_BLOCK_KEYS[4]),
            Value::Binary(charter.stamped_aggregate.to_vec()),
        ),
        (
            Value::from(CHARTER_BLOCK_KEYS[5]),
            Value::from(charter.stamped_by.clone()),
        ),
        (
            Value::from(CHARTER_BLOCK_KEYS[6]),
            Value::from(charter.stamped_at),
        ),
    ])
}

fn encode_catalog_entry(entry: &ConnectorCatalogEntry) -> Value {
    Value::Map(vec![
        (
            Value::from(CATALOG_ENTRY_KEYS[0]),
            Value::from(entry.name.clone()),
        ),
        (
            Value::from(CATALOG_ENTRY_KEYS[1]),
            Value::from(entry.connector.clone()),
        ),
        (
            Value::from(CATALOG_ENTRY_KEYS[2]),
            Value::from(entry.summary.clone()),
        ),
        (
            Value::from(CATALOG_ENTRY_KEYS[3]),
            Value::Array(
                entry
                    .verbs
                    .iter()
                    .map(|verb| Value::from(verb.clone()))
                    .collect(),
            ),
        ),
        (
            Value::from(CATALOG_ENTRY_KEYS[4]),
            Value::from(entry.call_class.as_str()),
        ),
        (
            Value::from(CATALOG_ENTRY_KEYS[5]),
            Value::from(entry.registered_at),
        ),
    ])
}

fn encode_pending_charter(pending: &PendingConnectorCharter) -> Value {
    Value::Map(vec![
        (
            Value::from(PENDING_CHARTER_KEYS[0]),
            Value::from(pending.text.clone()),
        ),
        (
            Value::from(PENDING_CHARTER_KEYS[1]),
            Value::Binary(pending.text_hash.to_vec()),
        ),
        (
            Value::from(PENDING_CHARTER_KEYS[2]),
            encode_compiled_policy(&pending.compiled),
        ),
        (
            Value::from(PENDING_CHARTER_KEYS[3]),
            Value::Binary(pending.compiled_hash.to_vec()),
        ),
        (
            Value::from(PENDING_CHARTER_KEYS[4]),
            Value::from(pending.proposed_at),
        ),
    ])
}

// --- Decoding ---------------------------------------------------------------

/// Decodes a ConnectorKeyRecord body after fail-closed structural validation.
pub fn decode_connector_key_body(bytes: &[u8]) -> Result<ConnectorKeyRecord> {
    let mut cursor = Cursor::new(bytes);
    let value = rmpv::decode::read_value(&mut cursor).map_err(|_| malformed())?;
    if cursor.position() != bytes.len() as u64 {
        return Err(malformed());
    }
    decode_connector_key_value(&value)
}

fn malformed() -> Error {
    invalid_body("body failed validation")
}

fn decode_connector_key_value(value: &Value) -> Result<ConnectorKeyRecord> {
    let Value::Map(entries) = value else {
        return Err(malformed());
    };
    validate_connector_key_body_keys(entries)?;

    let schema_version = required_value(entries, KEY_SCHEMA_VERSION)?.as_u64();
    if !matches!(schema_version, Some(1..=CONNECTOR_KEY_SCHEMA_VERSION)) {
        return Err(invalid_body("unsupported schema version"));
    }

    let record = ConnectorKeyRecord {
        connector: decode_non_empty_string(required_value(entries, KEY_CONNECTOR)?)?,
        actor_entity_ref: decode_optional_entity_id(required_value(
            entries,
            KEY_ACTOR_ENTITY_REF,
        )?)?,
        status: required_value(entries, KEY_STATUS)?
            .as_str()
            .and_then(ConnectorKeyStatus::parse)
            .ok_or_else(malformed)?,
        budgets: decode_budget_rows(required_value(entries, KEY_BUDGETS)?)?,
        registered_at: required_value(entries, KEY_REGISTERED_AT)?
            .as_u64()
            .ok_or_else(malformed)?,
        status_changed_at: decode_optional_u64(required_value(entries, KEY_STATUS_CHANGED_AT)?)?,
        suspended_reason: decode_optional_string(required_value(entries, KEY_SUSPENDED_REASON)?)?,
        charter: decode_optional_charter_block(required_value(entries, KEY_CHARTER)?)?,
        pending_charter: decode_optional_pending_charter(required_value(
            entries,
            KEY_PENDING_CHARTER,
        )?)?,
        suggested_budgets: optional_value(entries, KEY_SUGGESTED_BUDGETS)
            .map_or_else(|| Ok(Vec::new()), decode_budget_rows)?,
        // The v3 (ONE-1886) trio: absent on every stored v1/v2 body, which
        // therefore reads back unreferenced, at generation 0, and
        // unclassified — the pre-live-transport defaults.
        secret_ref: optional_value(entries, KEY_SECRET_REF)
            .map_or_else(|| Ok(None), decode_optional_string)?,
        key_generation: optional_value(entries, KEY_KEY_GENERATION)
            .map_or_else(|| Ok(0), decode_key_generation)?,
        catalog: optional_value(entries, KEY_CATALOG)
            .map_or_else(|| Ok(None), decode_optional_catalog_entry)?,
    };
    record.validate()?;
    Ok(record)
}

fn decode_key_generation(value: &Value) -> Result<u32> {
    let generation = value.as_u64().ok_or_else(malformed)?;
    u32::try_from(generation).map_err(|_| malformed())
}

fn decode_optional_catalog_entry(value: &Value) -> Result<Option<ConnectorCatalogEntry>> {
    if matches!(value, Value::Nil) {
        return Ok(None);
    }
    let Value::Map(entries) = value else {
        return Err(malformed());
    };
    validate_keys(entries, &CATALOG_ENTRY_KEYS)?;
    let Value::Array(verbs) = required_value(entries, CATALOG_ENTRY_KEYS[3])? else {
        return Err(malformed());
    };
    Ok(Some(ConnectorCatalogEntry {
        name: decode_non_empty_string(required_value(entries, CATALOG_ENTRY_KEYS[0])?)?,
        connector: decode_non_empty_string(required_value(entries, CATALOG_ENTRY_KEYS[1])?)?,
        summary: decode_non_empty_string(required_value(entries, CATALOG_ENTRY_KEYS[2])?)?,
        verbs: verbs
            .iter()
            .map(decode_non_empty_string)
            .collect::<Result<Vec<_>>>()?,
        call_class: required_value(entries, CATALOG_ENTRY_KEYS[4])?
            .as_str()
            .and_then(ConnectorCallClass::parse)
            .ok_or_else(malformed)?,
        registered_at: required_value(entries, CATALOG_ENTRY_KEYS[5])?
            .as_u64()
            .ok_or_else(malformed)?,
    }))
}

fn decode_budget_rows(value: &Value) -> Result<Vec<EffectorBudget>> {
    let Value::Array(rows) = value else {
        return Err(malformed());
    };
    rows.iter().map(decode_budget_row).collect()
}

fn decode_budget_row(value: &Value) -> Result<EffectorBudget> {
    let Value::Map(entries) = value else {
        return Err(malformed());
    };
    validate_keys(entries, &BUDGET_KEYS)?;
    let reserve_policy = match required_value(entries, BUDGET_KEYS[6])? {
        Value::Nil => None,
        value => Some(
            value
                .as_str()
                .and_then(EffectorBudgetReservePolicy::parse)
                .ok_or_else(malformed)?,
        ),
    };
    Ok(EffectorBudget {
        dimension: required_value(entries, BUDGET_KEYS[0])?
            .as_str()
            .and_then(EffectorBudgetDimension::parse)
            .ok_or_else(malformed)?,
        channel_class: decode_optional_string(required_value(entries, BUDGET_KEYS[1])?)?,
        limit: required_value(entries, BUDGET_KEYS[2])?
            .as_u64()
            .ok_or_else(malformed)?,
        unit: decode_optional_string(required_value(entries, BUDGET_KEYS[3])?)?,
        window: decode_window(required_value(entries, BUDGET_KEYS[4])?)?,
        on_exhaust: required_value(entries, BUDGET_KEYS[5])?
            .as_str()
            .and_then(EffectorBudgetOnExhaust::parse)
            .ok_or_else(malformed)?,
        reserve_policy,
    })
}

fn decode_window(value: &Value) -> Result<EffectorBudgetWindow> {
    let Value::Map(entries) = value else {
        return Err(malformed());
    };
    let kind = required_value(entries, "kind")?
        .as_str()
        .ok_or_else(malformed)?;
    match kind {
        WINDOW_KIND_ROLLING => {
            validate_keys(entries, &ROLLING_WINDOW_KEYS)?;
            Ok(EffectorBudgetWindow::Rolling {
                duration_s: required_value(entries, ROLLING_WINDOW_KEYS[1])?
                    .as_u64()
                    .ok_or_else(malformed)?,
            })
        }
        WINDOW_KIND_CALENDAR => {
            validate_keys(entries, &CALENDAR_WINDOW_KEYS)?;
            Ok(EffectorBudgetWindow::Calendar {
                period: required_value(entries, CALENDAR_WINDOW_KEYS[1])?
                    .as_str()
                    .and_then(CalendarPeriod::parse)
                    .ok_or_else(malformed)?,
                tz: decode_optional_string(required_value(entries, CALENDAR_WINDOW_KEYS[2])?)?,
            })
        }
        _ => Err(malformed()),
    }
}

fn decode_compiled_policy(value: &Value) -> Result<CompiledConnectorPolicy> {
    let Value::Map(entries) = value else {
        return Err(malformed());
    };
    validate_keys(entries, &COMPILED_POLICY_KEYS)?;
    let Value::Array(never_entries) = required_value(entries, COMPILED_POLICY_KEYS[0])? else {
        return Err(malformed());
    };
    let never_list = never_entries
        .iter()
        .map(|entry| entry.as_str().map(str::to_owned).ok_or_else(malformed))
        .collect::<Result<Vec<_>>>()?;
    Ok(CompiledConnectorPolicy {
        never_list,
        channel_caps: decode_budget_rows(required_value(entries, COMPILED_POLICY_KEYS[1])?)?,
    })
}

fn decode_optional_charter_block(value: &Value) -> Result<Option<ConnectorCharterBlock>> {
    if matches!(value, Value::Nil) {
        return Ok(None);
    }
    let Value::Map(entries) = value else {
        return Err(malformed());
    };
    validate_keys(entries, &CHARTER_BLOCK_KEYS)?;
    Ok(Some(ConnectorCharterBlock {
        text: decode_non_empty_string(required_value(entries, CHARTER_BLOCK_KEYS[0])?)?,
        text_hash: decode_hash32(required_value(entries, CHARTER_BLOCK_KEYS[1])?)?,
        compiled: decode_compiled_policy(required_value(entries, CHARTER_BLOCK_KEYS[2])?)?,
        compiled_hash: decode_hash32(required_value(entries, CHARTER_BLOCK_KEYS[3])?)?,
        stamped_aggregate: decode_hash32(required_value(entries, CHARTER_BLOCK_KEYS[4])?)?,
        stamped_by: decode_non_empty_string(required_value(entries, CHARTER_BLOCK_KEYS[5])?)?,
        stamped_at: required_value(entries, CHARTER_BLOCK_KEYS[6])?
            .as_u64()
            .ok_or_else(malformed)?,
    }))
}

fn decode_optional_pending_charter(value: &Value) -> Result<Option<PendingConnectorCharter>> {
    if matches!(value, Value::Nil) {
        return Ok(None);
    }
    let Value::Map(entries) = value else {
        return Err(malformed());
    };
    validate_keys(entries, &PENDING_CHARTER_KEYS)?;
    Ok(Some(PendingConnectorCharter {
        text: decode_non_empty_string(required_value(entries, PENDING_CHARTER_KEYS[0])?)?,
        text_hash: decode_hash32(required_value(entries, PENDING_CHARTER_KEYS[1])?)?,
        compiled: decode_compiled_policy(required_value(entries, PENDING_CHARTER_KEYS[2])?)?,
        compiled_hash: decode_hash32(required_value(entries, PENDING_CHARTER_KEYS[3])?)?,
        proposed_at: required_value(entries, PENDING_CHARTER_KEYS[4])?
            .as_u64()
            .ok_or_else(malformed)?,
    }))
}

fn validate_keys(entries: &[(Value, Value)], keys: &[&str]) -> Result<()> {
    let mut seen = vec![false; keys.len()];
    for (key, _) in entries {
        let key = key.as_str().ok_or_else(malformed)?;
        let Some(index) = keys.iter().position(|known| *known == key) else {
            return Err(malformed());
        };
        if seen[index] {
            return Err(malformed());
        }
        seen[index] = true;
    }
    if seen.into_iter().all(|value| value) {
        Ok(())
    } else {
        Err(malformed())
    }
}

fn validate_connector_key_body_keys(entries: &[(Value, Value)]) -> Result<()> {
    let mut seen = vec![false; CONNECTOR_KEY_BODY_KEYS.len()];
    for (key, _) in entries {
        let key = key.as_str().ok_or_else(malformed)?;
        let Some(index) = CONNECTOR_KEY_BODY_KEYS
            .iter()
            .position(|known| *known == key)
        else {
            return Err(malformed());
        };
        if seen[index] {
            return Err(malformed());
        }
        seen[index] = true;
    }
    for (index, key) in CONNECTOR_KEY_BODY_KEYS.iter().enumerate() {
        if !seen[index] && !OPTIONAL_CONNECTOR_KEY_BODY_KEYS.contains(key) {
            return Err(malformed());
        }
    }
    Ok(())
}

fn required_value<'a>(entries: &'a [(Value, Value)], key: &str) -> Result<&'a Value> {
    entries
        .iter()
        .find_map(|(candidate, value)| (candidate.as_str() == Some(key)).then_some(value))
        .ok_or_else(malformed)
}

fn optional_value<'a>(entries: &'a [(Value, Value)], key: &str) -> Option<&'a Value> {
    entries
        .iter()
        .find_map(|(candidate, value)| (candidate.as_str() == Some(key)).then_some(value))
}

fn decode_non_empty_string(value: &Value) -> Result<String> {
    let value = value.as_str().ok_or_else(malformed)?;
    if value.trim().is_empty() {
        return Err(malformed());
    }
    Ok(value.to_owned())
}

fn decode_optional_string(value: &Value) -> Result<Option<String>> {
    if matches!(value, Value::Nil) {
        return Ok(None);
    }
    decode_non_empty_string(value).map(Some)
}

fn decode_optional_u64(value: &Value) -> Result<Option<u64>> {
    if matches!(value, Value::Nil) {
        return Ok(None);
    }
    value.as_u64().ok_or_else(malformed).map(Some)
}

fn decode_optional_entity_id(value: &Value) -> Result<Option<EntityId>> {
    match value {
        Value::Nil => Ok(None),
        Value::Binary(bytes) => {
            let raw: [u8; ENTITY_ID_LEN] = bytes.as_slice().try_into().map_err(|_| malformed())?;
            EntityId::from_bytes(raw).map(Some).map_err(|_| malformed())
        }
        _ => Err(malformed()),
    }
}

fn decode_hash32(value: &Value) -> Result<[u8; 32]> {
    let Value::Binary(bytes) = value else {
        return Err(malformed());
    };
    bytes.as_slice().try_into().map_err(|_| malformed())
}

fn option_string_value(value: Option<&str>) -> Value {
    value.map_or(Value::Nil, Value::from)
}
