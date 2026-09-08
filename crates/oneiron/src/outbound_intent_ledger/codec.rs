//! Pinned key sets, content digest, and MessagePack encode/decode.

use std::io::Cursor;

use rmpv::Value;

use super::store::validate_record;
use super::types::{
    BudgetChargeMarker, BudgetClass, INTENT_LEDGER_SCHEMA_VERSION, IntentEscalationReason,
    IntentLedgerError, IntentLedgerRecord, IntentLedgerResult, IntentState,
    OutboundAuthorizationBinding, RecordedOutboundOutcome,
};
use crate::attempt_queue::AttemptId;
use crate::connector_key::ScopedCapabilityProvenance;
use crate::entity_id::EntityId;

/// Pinned MessagePack key set for device-local outbound intent rows.
pub const INTENT_LEDGER_VALUE_KEYS: [&str; 20] = [
    "schema_version",
    "id",
    "attempt_id",
    "call_seq",
    "server",
    "tool",
    "payload_hash",
    "payload",
    "idempotency_key",
    "idempotency_supported",
    "authorization_binding",
    "binding_version",
    "resolved_endpoint",
    "capability_provenance",
    "budget_accounting",
    "recorded_outcome",
    "state",
    "created_ms",
    "updated_ms",
    "content_digest",
];

pub(super) const INTENT_LEDGER_PRIVATE_PREFIX: &[u8] = b"outbound:intent_ledger:v2:"; // + id(32)

const BUDGET_ACCOUNTING_KEYS: [&str; 5] = [
    "key_ref",
    "budget_class",
    "matched_rows",
    "sends_debit",
    "accounted_at_ms",
];

const RECORDED_OUTCOME_KEYS: [&str; 2] = ["kind", "reason"];

/// Pinned nested key set for the typed scoped capability provenance.
pub(super) const CAPABILITY_PROVENANCE_KEYS: [&str; 3] = ["grant_id", "server", "connector"];

pub(super) const KEY_SCHEMA_VERSION: &str = INTENT_LEDGER_VALUE_KEYS[0];

pub(super) const KEY_ID: &str = INTENT_LEDGER_VALUE_KEYS[1];

pub(super) const KEY_ATTEMPT_ID: &str = INTENT_LEDGER_VALUE_KEYS[2];

pub(super) const KEY_CALL_SEQ: &str = INTENT_LEDGER_VALUE_KEYS[3];

pub(super) const KEY_SERVER: &str = INTENT_LEDGER_VALUE_KEYS[4];

pub(super) const KEY_TOOL: &str = INTENT_LEDGER_VALUE_KEYS[5];

pub(super) const KEY_PAYLOAD_HASH: &str = INTENT_LEDGER_VALUE_KEYS[6];

pub(super) const KEY_PAYLOAD: &str = INTENT_LEDGER_VALUE_KEYS[7];

pub(super) const KEY_IDEMPOTENCY_KEY: &str = INTENT_LEDGER_VALUE_KEYS[8];

pub(super) const KEY_IDEMPOTENCY_SUPPORTED: &str = INTENT_LEDGER_VALUE_KEYS[9];

pub(super) const KEY_AUTHORIZATION_BINDING: &str = INTENT_LEDGER_VALUE_KEYS[10];

pub(super) const KEY_BINDING_VERSION: &str = INTENT_LEDGER_VALUE_KEYS[11];

pub(super) const KEY_RESOLVED_ENDPOINT: &str = INTENT_LEDGER_VALUE_KEYS[12];

pub(super) const KEY_CAPABILITY_PROVENANCE: &str = INTENT_LEDGER_VALUE_KEYS[13];

pub(super) const KEY_BUDGET_ACCOUNTING: &str = INTENT_LEDGER_VALUE_KEYS[14];

pub(super) const KEY_RECORDED_OUTCOME: &str = INTENT_LEDGER_VALUE_KEYS[15];

pub(super) const KEY_STATE: &str = INTENT_LEDGER_VALUE_KEYS[16];

pub(super) const KEY_CREATED_MS: &str = INTENT_LEDGER_VALUE_KEYS[17];

pub(super) const KEY_UPDATED_MS: &str = INTENT_LEDGER_VALUE_KEYS[18];

pub(super) const KEY_CONTENT_DIGEST: &str = INTENT_LEDGER_VALUE_KEYS[19];

/// The canonical intent body used as the digest preimage.
///
/// Entries are exactly `INTENT_LEDGER_VALUE_KEYS[0..19]`, in that order, with
/// `KEY_CONTENT_DIGEST` absent. This is the single source of every stored body
/// value — raw payload, authorization binding, nested budget accounting, typed
/// capability provenance, recorded outcome, state, and timestamps — so the
/// digested bytes and the persisted bytes cannot drift into two representations
/// of one row.
fn record_entries_without_digest(record: &IntentLedgerRecord) -> Vec<(Value, Value)> {
    let budget_accounting = Value::Map(vec![
        (
            Value::from(BUDGET_ACCOUNTING_KEYS[0]),
            record
                .budget_accounting
                .key_ref
                .as_ref()
                .map_or(Value::Nil, |id| Value::Binary(id.as_bytes().to_vec())),
        ),
        (
            Value::from(BUDGET_ACCOUNTING_KEYS[1]),
            Value::from(record.budget_accounting.budget_class.as_str()),
        ),
        (
            Value::from(BUDGET_ACCOUNTING_KEYS[2]),
            Value::Array(
                record
                    .budget_accounting
                    .matched_rows
                    .iter()
                    .map(|row| Value::from(u64::from(*row)))
                    .collect(),
            ),
        ),
        (
            Value::from(BUDGET_ACCOUNTING_KEYS[3]),
            Value::from(record.budget_accounting.sends_debit),
        ),
        (
            Value::from(BUDGET_ACCOUNTING_KEYS[4]),
            Value::from(record.budget_accounting.accounted_at_ms),
        ),
    ]);
    let capability_provenance =
        record
            .capability_provenance
            .as_ref()
            .map_or(Value::Nil, |capability| {
                Value::Map(vec![
                    (
                        Value::from(CAPABILITY_PROVENANCE_KEYS[0]),
                        Value::Binary(capability.grant_id().as_bytes().to_vec()),
                    ),
                    (
                        Value::from(CAPABILITY_PROVENANCE_KEYS[1]),
                        Value::from(capability.server()),
                    ),
                    (
                        Value::from(CAPABILITY_PROVENANCE_KEYS[2]),
                        Value::from(capability.connector()),
                    ),
                ])
            });
    let recorded_outcome = record.recorded_outcome.map_or(Value::Nil, |outcome| {
        let (kind, reason) = match outcome {
            RecordedOutboundOutcome::DefiniteNonDelivery => ("definite_non_delivery", Value::Nil),
            RecordedOutboundOutcome::Acked => ("acked", Value::Nil),
            RecordedOutboundOutcome::Abandoned(reason) => {
                ("abandoned", Value::from(reason.as_str()))
            }
        };
        Value::Map(vec![
            (Value::from(RECORDED_OUTCOME_KEYS[0]), Value::from(kind)),
            (Value::from(RECORDED_OUTCOME_KEYS[1]), reason),
        ])
    });
    vec![
        (
            Value::from(KEY_SCHEMA_VERSION),
            Value::from(INTENT_LEDGER_SCHEMA_VERSION),
        ),
        (Value::from(KEY_ID), Value::Binary(record.id.to_vec())),
        (
            Value::from(KEY_ATTEMPT_ID),
            Value::Binary(record.attempt_id.as_bytes().to_vec()),
        ),
        (Value::from(KEY_CALL_SEQ), Value::from(record.call_seq)),
        (Value::from(KEY_SERVER), Value::from(record.server.as_str())),
        (Value::from(KEY_TOOL), Value::from(record.tool.as_str())),
        (
            Value::from(KEY_PAYLOAD_HASH),
            Value::Binary(record.payload_hash.to_vec()),
        ),
        (
            Value::from(KEY_PAYLOAD),
            Value::Binary(record.payload.clone()),
        ),
        (
            Value::from(KEY_IDEMPOTENCY_KEY),
            Value::from(record.idempotency_key.as_str()),
        ),
        (
            Value::from(KEY_IDEMPOTENCY_SUPPORTED),
            Value::Boolean(record.idempotency_supported),
        ),
        (
            Value::from(KEY_AUTHORIZATION_BINDING),
            record
                .authorization_binding
                .as_ref()
                .map_or(Value::Nil, |binding| {
                    Value::Binary(binding.as_bytes().to_vec())
                }),
        ),
        (
            Value::from(KEY_BINDING_VERSION),
            Value::from(record.binding_version),
        ),
        (
            Value::from(KEY_RESOLVED_ENDPOINT),
            record
                .resolved_endpoint
                .as_deref()
                .map_or(Value::Nil, Value::from),
        ),
        (
            Value::from(KEY_CAPABILITY_PROVENANCE),
            capability_provenance,
        ),
        (Value::from(KEY_BUDGET_ACCOUNTING), budget_accounting),
        (Value::from(KEY_RECORDED_OUTCOME), recorded_outcome),
        (Value::from(KEY_STATE), Value::from(record.state.as_str())),
        (Value::from(KEY_CREATED_MS), Value::from(record.created_ms)),
        (Value::from(KEY_UPDATED_MS), Value::from(record.updated_ms)),
    ]
}

/// Encodes `Value::Map(record_entries_without_digest(record))`.
///
/// The 19-entry MessagePack map header is part of the preimage, and so are the
/// raw `payload` bytes: the preimage is definitionally the stored body minus
/// the digest key, and carving `payload` out would reintroduce a second body
/// representation. The O(payload) cost per encode/decode is accepted;
/// `payload_hash` stays separately validated by `validate_record`.
pub(super) fn encode_record_digest_preimage(
    record: &IntentLedgerRecord,
) -> IntentLedgerResult<Vec<u8>> {
    encode_messagepack_map(record_entries_without_digest(record))
}

/// Unkeyed BLAKE3 over the canonical body, with no domain prefix or suffix
/// beyond the encoded row: this preserves the shipped direct-BLAKE3 convention,
/// and there is no algorithm tag, alternate verifier, or old-digest acceptance
/// branch. This path never traverses serde JSON; `derive_intent_id` alone owns
/// the canonical-JSON identity preimage.
pub(super) fn record_content_digest(record: &IntentLedgerRecord) -> IntentLedgerResult<[u8; 32]> {
    let preimage = encode_record_digest_preimage(record)?;
    Ok(*blake3::hash(&preimage).as_bytes())
}

fn encode_messagepack_map(entries: Vec<(Value, Value)>) -> IntentLedgerResult<Vec<u8>> {
    let mut encoded = Vec::new();
    rmpv::encode::write_value(&mut encoded, &Value::Map(entries)).map_err(|_| {
        IntentLedgerError::InvalidRecord("outbound intent MessagePack encode failed")
    })?;
    Ok(encoded)
}

pub(super) fn intent_ledger_key(id: &[u8; 32]) -> Vec<u8> {
    let mut key = Vec::with_capacity(INTENT_LEDGER_PRIVATE_PREFIX.len() + id.len());
    key.extend_from_slice(INTENT_LEDGER_PRIVATE_PREFIX);
    key.extend_from_slice(id);
    key
}

pub(super) fn id_from_ledger_key(key: &[u8]) -> Option<[u8; 32]> {
    if key.len() != INTENT_LEDGER_PRIVATE_PREFIX.len() + 32
        || !key.starts_with(INTENT_LEDGER_PRIVATE_PREFIX)
    {
        return None;
    }
    key[INTENT_LEDGER_PRIVATE_PREFIX.len()..].try_into().ok()
}

/// Encodes the canonical 20-entry row: the digest preimage body plus the
/// content digest computed over exactly those bytes, appended as the final
/// `content_digest` entry.
pub(super) fn encode_record(record: &IntentLedgerRecord) -> IntentLedgerResult<Vec<u8>> {
    let digest = record_content_digest(record)?;
    let mut entries = record_entries_without_digest(record);
    entries.push((
        Value::from(KEY_CONTENT_DIGEST),
        Value::Binary(digest.to_vec()),
    ));
    encode_messagepack_map(entries)
}

pub(super) fn decode_record(key: &[u8], raw: &[u8]) -> IntentLedgerResult<IntentLedgerRecord> {
    let mut cursor = Cursor::new(raw);
    let value = rmpv::decode::read_value(&mut cursor).map_err(|_| {
        IntentLedgerError::InvalidRecord("outbound intent MessagePack decode failed")
    })?;
    if cursor.position() != raw.len() as u64 {
        return Err(IntentLedgerError::InvalidRecord(
            "outbound intent row has trailing bytes",
        ));
    }
    let Value::Map(entries) = value else {
        return Err(IntentLedgerError::InvalidRecord(
            "outbound intent row must be a MessagePack map",
        ));
    };

    let mut schema_version = None;
    let mut id = None;
    let mut attempt_id = None;
    let mut call_seq = None;
    let mut server = None;
    let mut tool = None;
    let mut payload_hash = None;
    let mut payload = None;
    let mut idempotency_key = None;
    let mut idempotency_supported = None;
    let mut authorization_binding = None;
    let mut binding_version = None;
    let mut resolved_endpoint = None;
    let mut capability_provenance = None;
    let mut budget_accounting = None;
    let mut recorded_outcome = None;
    let mut state = None;
    let mut created_ms = None;
    let mut updated_ms = None;
    let mut content_digest = None;
    let mut seen = [false; INTENT_LEDGER_VALUE_KEYS.len()];

    for (entry_key, value) in entries {
        let entry_key = entry_key.as_str().ok_or(IntentLedgerError::InvalidRecord(
            "outbound intent keys must be strings",
        ))?;
        let index = INTENT_LEDGER_VALUE_KEYS
            .iter()
            .position(|candidate| *candidate == entry_key)
            .ok_or(IntentLedgerError::InvalidRecord(
                "outbound intent key is not pinned",
            ))?;
        if seen[index] {
            return Err(IntentLedgerError::InvalidRecord(
                "duplicate outbound intent key",
            ));
        }
        seen[index] = true;

        match INTENT_LEDGER_VALUE_KEYS[index] {
            KEY_SCHEMA_VERSION => schema_version = Some(expect_u64(&value)?),
            KEY_ID => id = Some(expect_binary_array::<32>(&value)?),
            KEY_ATTEMPT_ID => {
                let bytes = expect_binary_array::<16>(&value)?;
                attempt_id = Some(AttemptId::from_bytes(&bytes)?);
            }
            KEY_CALL_SEQ => call_seq = Some(expect_u64(&value)?),
            KEY_SERVER => server = Some(expect_string(&value)?),
            KEY_TOOL => tool = Some(expect_string(&value)?),
            KEY_PAYLOAD_HASH => payload_hash = Some(expect_binary_array::<32>(&value)?),
            KEY_PAYLOAD => payload = Some(expect_binary(&value)?),
            KEY_IDEMPOTENCY_KEY => idempotency_key = Some(expect_string(&value)?),
            KEY_IDEMPOTENCY_SUPPORTED => {
                idempotency_supported =
                    Some(value.as_bool().ok_or(IntentLedgerError::InvalidRecord(
                        "outbound intent idempotency_supported must be boolean",
                    ))?);
            }
            KEY_AUTHORIZATION_BINDING => {
                authorization_binding = Some(if matches!(value, Value::Nil) {
                    None
                } else {
                    Some(OutboundAuthorizationBinding::new(
                        expect_binary_array::<32>(&value)?,
                    ))
                });
            }
            KEY_BINDING_VERSION => binding_version = Some(expect_u64(&value)?),
            KEY_RESOLVED_ENDPOINT => {
                resolved_endpoint = Some(if matches!(value, Value::Nil) {
                    None
                } else {
                    Some(expect_string(&value)?)
                });
            }
            KEY_CAPABILITY_PROVENANCE => {
                capability_provenance = Some(decode_capability_provenance(&value)?);
            }
            KEY_BUDGET_ACCOUNTING => budget_accounting = Some(decode_budget_accounting(&value)?),
            KEY_RECORDED_OUTCOME => {
                recorded_outcome = Some(decode_recorded_outcome(&value)?);
            }
            KEY_STATE => {
                state = Some(
                    IntentState::parse(value.as_str().ok_or(IntentLedgerError::InvalidRecord(
                        "outbound intent state must be a string",
                    ))?)
                    .ok_or(IntentLedgerError::InvalidRecord(
                        "unknown outbound intent state",
                    ))?,
                );
            }
            KEY_CREATED_MS => created_ms = Some(expect_u64(&value)?),
            KEY_UPDATED_MS => updated_ms = Some(expect_u64(&value)?),
            KEY_CONTENT_DIGEST => content_digest = Some(expect_binary_array::<32>(&value)?),
            _ => {
                return Err(IntentLedgerError::InvalidRecord(
                    "outbound intent pinned key has no decoder",
                ));
            }
        }
    }

    let schema_version = required(schema_version, "missing outbound intent schema_version")?;
    if schema_version != INTENT_LEDGER_SCHEMA_VERSION {
        return Err(IntentLedgerError::InvalidRecord(
            "unsupported outbound intent schema_version",
        ));
    }
    let record = IntentLedgerRecord {
        id: required(id, "missing outbound intent id")?,
        attempt_id: required(attempt_id, "missing outbound intent attempt_id")?,
        call_seq: required(call_seq, "missing outbound intent call_seq")?,
        server: required(server, "missing outbound intent server")?,
        tool: required(tool, "missing outbound intent tool")?,
        payload_hash: required(payload_hash, "missing outbound intent payload_hash")?,
        payload: required(payload, "missing outbound intent payload")?,
        idempotency_key: required(idempotency_key, "missing outbound intent idempotency_key")?,
        idempotency_supported: required(
            idempotency_supported,
            "missing outbound intent idempotency_supported",
        )?,
        authorization_binding: required(
            authorization_binding,
            "missing outbound intent authorization_binding",
        )?,
        binding_version: required(binding_version, "missing outbound intent binding_version")?,
        resolved_endpoint: required(
            resolved_endpoint,
            "missing outbound intent resolved_endpoint",
        )?,
        capability_provenance: required(
            capability_provenance,
            "missing outbound intent capability_provenance",
        )?,
        budget_accounting: required(
            budget_accounting,
            "missing outbound intent budget_accounting",
        )?,
        recorded_outcome: required(recorded_outcome, "missing outbound intent recorded_outcome")?,
        state: required(state, "missing outbound intent state")?,
        created_ms: required(created_ms, "missing outbound intent created_ms")?,
        updated_ms: required(updated_ms, "missing outbound intent updated_ms")?,
    };
    let content_digest = required(content_digest, "missing outbound intent content_digest")?;
    if record_content_digest(&record)? != content_digest {
        return Err(IntentLedgerError::InvalidRecord(
            "outbound intent content digest mismatch",
        ));
    }
    validate_record(key, &record)?;
    Ok(record)
}

fn decode_budget_accounting(value: &Value) -> IntentLedgerResult<BudgetChargeMarker> {
    let Value::Map(entries) = value else {
        return Err(IntentLedgerError::InvalidRecord(
            "outbound intent budget_accounting must be a map",
        ));
    };
    validate_nested_keys(entries, &BUDGET_ACCOUNTING_KEYS)?;
    let key_ref = match nested_value(entries, BUDGET_ACCOUNTING_KEYS[0])? {
        Value::Nil => None,
        value => Some(
            EntityId::from_bytes(expect_binary_array::<16>(value)?).map_err(|_| {
                IntentLedgerError::InvalidRecord("outbound intent budget key_ref is invalid")
            })?,
        ),
    };
    let budget_class = nested_value(entries, BUDGET_ACCOUNTING_KEYS[1])?
        .as_str()
        .and_then(BudgetClass::parse)
        .ok_or(IntentLedgerError::InvalidRecord(
            "outbound intent budget_class is invalid",
        ))?;
    let Value::Array(row_values) = nested_value(entries, BUDGET_ACCOUNTING_KEYS[2])? else {
        return Err(IntentLedgerError::InvalidRecord(
            "outbound intent matched_rows must be an array",
        ));
    };
    let mut matched_rows = Vec::with_capacity(row_values.len());
    for value in row_values {
        let row = expect_u64(value)?;
        matched_rows.push(u16::try_from(row).map_err(|_| {
            IntentLedgerError::InvalidRecord("outbound intent matched row is invalid")
        })?);
    }
    Ok(BudgetChargeMarker {
        key_ref,
        budget_class,
        matched_rows,
        sends_debit: expect_u64(nested_value(entries, BUDGET_ACCOUNTING_KEYS[3])?)?,
        accounted_at_ms: expect_u64(nested_value(entries, BUDGET_ACCOUNTING_KEYS[4])?)?,
    })
}

/// Decodes the typed scoped capability provenance fail-closed: unknown or
/// duplicate nested keys, a malformed grant id, an unsafe/non-canonical server,
/// or a connector that is not EXACTLY the identity that (server, grant) mints
/// are all rejected, so no durable row can carry a forged capability (ONE-1885).
fn decode_capability_provenance(
    value: &Value,
) -> IntentLedgerResult<Option<ScopedCapabilityProvenance>> {
    if matches!(value, Value::Nil) {
        return Ok(None);
    }
    let Value::Map(entries) = value else {
        return Err(IntentLedgerError::InvalidRecord(
            "outbound intent capability_provenance must be a map",
        ));
    };
    validate_nested_keys(entries, &CAPABILITY_PROVENANCE_KEYS)?;
    let grant_id = EntityId::from_bytes(expect_binary_array::<16>(nested_value(
        entries,
        CAPABILITY_PROVENANCE_KEYS[0],
    )?)?)
    .map_err(|_| {
        IntentLedgerError::InvalidRecord("outbound intent capability grant_id is invalid")
    })?;
    let server = expect_string(nested_value(entries, CAPABILITY_PROVENANCE_KEYS[1])?)?;
    let connector = expect_string(nested_value(entries, CAPABILITY_PROVENANCE_KEYS[2])?)?;
    ScopedCapabilityProvenance::from_persisted_parts(&grant_id, &server, &connector)
        .map(Some)
        .ok_or(IntentLedgerError::InvalidRecord(
            "outbound intent capability_provenance is inconsistent",
        ))
}

fn decode_recorded_outcome(value: &Value) -> IntentLedgerResult<Option<RecordedOutboundOutcome>> {
    if matches!(value, Value::Nil) {
        return Ok(None);
    }
    let Value::Map(entries) = value else {
        return Err(IntentLedgerError::InvalidRecord(
            "outbound intent recorded_outcome must be a map",
        ));
    };
    validate_nested_keys(entries, &RECORDED_OUTCOME_KEYS)?;
    let kind = nested_value(entries, RECORDED_OUTCOME_KEYS[0])?
        .as_str()
        .ok_or(IntentLedgerError::InvalidRecord(
            "outbound intent outcome kind is invalid",
        ))?;
    let reason = nested_value(entries, RECORDED_OUTCOME_KEYS[1])?;
    match (kind, reason) {
        ("definite_non_delivery", Value::Nil) => {
            Ok(Some(RecordedOutboundOutcome::DefiniteNonDelivery))
        }
        ("acked", Value::Nil) => Ok(Some(RecordedOutboundOutcome::Acked)),
        ("abandoned", value) => {
            let reason = value
                .as_str()
                .and_then(IntentEscalationReason::parse)
                .ok_or(IntentLedgerError::InvalidRecord(
                    "outbound intent abandonment reason is invalid",
                ))?;
            Ok(Some(RecordedOutboundOutcome::Abandoned(reason)))
        }
        _ => Err(IntentLedgerError::InvalidRecord(
            "outbound intent recorded_outcome is inconsistent",
        )),
    }
}

fn validate_nested_keys(entries: &[(Value, Value)], keys: &[&str]) -> IntentLedgerResult<()> {
    let mut seen = vec![false; keys.len()];
    for (key, _) in entries {
        let key = key.as_str().ok_or(IntentLedgerError::InvalidRecord(
            "outbound intent nested keys must be strings",
        ))?;
        let index = keys.iter().position(|candidate| *candidate == key).ok_or(
            IntentLedgerError::InvalidRecord("outbound intent nested key is not pinned"),
        )?;
        if seen[index] {
            return Err(IntentLedgerError::InvalidRecord(
                "duplicate outbound intent nested key",
            ));
        }
        seen[index] = true;
    }
    if seen.into_iter().all(|value| value) {
        Ok(())
    } else {
        Err(IntentLedgerError::InvalidRecord(
            "outbound intent nested field is missing",
        ))
    }
}

fn nested_value<'a>(entries: &'a [(Value, Value)], key: &str) -> IntentLedgerResult<&'a Value> {
    entries
        .iter()
        .find_map(|(candidate, value)| (candidate.as_str() == Some(key)).then_some(value))
        .ok_or(IntentLedgerError::InvalidRecord(
            "outbound intent nested field is missing",
        ))
}

fn expect_u64(value: &Value) -> IntentLedgerResult<u64> {
    value.as_u64().ok_or(IntentLedgerError::InvalidRecord(
        "outbound intent integer field is invalid",
    ))
}

fn expect_string(value: &Value) -> IntentLedgerResult<String> {
    value
        .as_str()
        .map(str::to_owned)
        .ok_or(IntentLedgerError::InvalidRecord(
            "outbound intent string field is invalid",
        ))
}

fn expect_binary(value: &Value) -> IntentLedgerResult<Vec<u8>> {
    let Value::Binary(bytes) = value else {
        return Err(IntentLedgerError::InvalidRecord(
            "outbound intent binary field is invalid",
        ));
    };
    Ok(bytes.clone())
}

fn expect_binary_array<const N: usize>(value: &Value) -> IntentLedgerResult<[u8; N]> {
    expect_binary(value)?
        .try_into()
        .map_err(|_| IntentLedgerError::InvalidRecord("outbound intent binary length is invalid"))
}

fn required<T>(value: Option<T>, reason: &'static str) -> IntentLedgerResult<T> {
    value.ok_or(IntentLedgerError::InvalidRecord(reason))
}
