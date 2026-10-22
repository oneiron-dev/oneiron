//! The task a released eval case was given, for the trusted measuring host
//! only (FIX 574, OF-578). It reads a member of a claimed measurement's
//! cohort, checked against the stored exposures and membership, never a
//! release a caller hands in. A case is replayable when it is one
//! `attempt:<hex>` receipt with no parents, whose kept attempt carries a
//! Dreamer payload with an input that reads as JSON exactly. Any other shape
//! is unavailable, never "whatever bytes look like text".

use rmpv::Value;
use serde_json::{Map, Number, Value as JsonValue};

use super::cohort::{cohort_in_txn, exposure_row_in_txn};
use super::measurement::{
    EvalMeasurement, MeasurementState, MeasurementUnavailable, measurement_in_txn,
};
use super::{EvalCase, EvalExposureKind, EvalLabel, case_in_txn};
use crate::Vault;
use crate::attempt_queue::{AttemptId, AttemptQueue};
use crate::dreamer_runner::decode_dreamer_attempt_payload;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};

/// A terminal pack receipt's namespace: `attempt:<32 hex>`.
const ATTEMPT_RECEIPT: &str = "attempt:";

/// One released case's task, as every leg of a measurement is given it.
#[derive(Debug, Clone, PartialEq)]
pub struct EvalTaskInput {
    pub case: EntityId,
    pub family: EntityId,
    pub stratum: Option<String>,
    /// The Dreamer job type the attempt ran.
    pub kind: String,
    /// The attempt's input, read as JSON exactly.
    pub input: JsonValue,
    /// The case's anchoring labels: the frozen check each answer is scored
    /// against.
    pub labels: Vec<EvalLabel>,
    /// BLAKE3 of the attempt's payload bytes.
    pub source_hash: [u8; 32],
    /// BLAKE3 of the input's JSON text: the task every leg is given.
    pub task_hash: [u8; 32],
    /// The rows the case and its labels were read from (FIX 5761); `None`
    /// when any is unknown.
    pub source_rows: Option<Vec<EntityId>>,
}

type Released = std::result::Result<EvalTaskInput, MeasurementUnavailable>;

/// `value` as JSON, exactly: a binary or extension value, a non-text key, a
/// repeated key or a non-finite number has no JSON reading.
fn strict_json(value: &Value) -> Option<JsonValue> {
    Some(match value {
        Value::Nil => JsonValue::Null,
        Value::Boolean(flag) => JsonValue::Bool(*flag),
        Value::Integer(number) => match number.as_u64() {
            Some(unsigned) => JsonValue::from(unsigned),
            None => JsonValue::from(number.as_i64()?),
        },
        Value::F32(number) => JsonValue::Number(Number::from_f64(f64::from(*number))?),
        Value::F64(number) => JsonValue::Number(Number::from_f64(*number)?),
        Value::String(text) => JsonValue::String(text.as_str()?.to_owned()),
        Value::Binary(_) | Value::Ext(..) => return None,
        Value::Array(items) => {
            JsonValue::Array(items.iter().map(strict_json).collect::<Option<_>>()?)
        }
        Value::Map(entries) => {
            let mut map = Map::new();
            for (key, item) in entries {
                if map
                    .insert(key.as_str()?.to_owned(), strict_json(item)?)
                    .is_some()
                {
                    return None;
                }
            }
            JsonValue::Object(map)
        }
    })
}

/// Whether the claim's stored exposures are this measurement's three
/// Candidate servings of its cohort.
fn released(vault: &Vault, txn: &heed::RoTxn<'_>, row: &EvalMeasurement) -> Result<bool> {
    if row.state != MeasurementState::Claimed || row.exposures.len() != 3 {
        return Ok(false);
    }
    let consumer = format!("eval_measurement:{}:", row.digest);
    for id in &row.exposures {
        let Some(exposure) = exposure_row_in_txn(vault, txn, &row.request.cohort, id)? else {
            return Ok(false);
        };
        if exposure.kind != EvalExposureKind::Candidate || !exposure.consumer.starts_with(&consumer)
        {
            return Ok(false);
        }
    }
    Ok(true)
}

/// The attempt a case replays, when it is one attempt receipt and no parents.
fn attempt_of(case: &EvalCase) -> Option<AttemptId> {
    let [receipt] = case.receipts.as_slice() else {
        return None;
    };
    if !case.parents.is_empty() {
        return None;
    }
    let id = EntityId::from_hex(receipt.strip_prefix(ATTEMPT_RECEIPT)?).ok()?;
    AttemptId::from_bytes(id.as_bytes()).ok()
}

/// The case's task from its kept attempt.
fn hydrate(vault: &Vault, txn: &heed::RoTxn<'_>, case: EvalCase) -> Result<Released> {
    let Some(attempt) = attempt_of(&case) else {
        return Ok(Err(MeasurementUnavailable::UnsupportedTaskPayload));
    };
    let Some(record) = AttemptQueue::new(vault).get_in_txn(txn, attempt)? else {
        return Ok(Err(MeasurementUnavailable::TaskGone));
    };
    let Ok(payload) = decode_dreamer_attempt_payload(&record.payload) else {
        return Ok(Err(MeasurementUnavailable::UnsupportedTaskPayload));
    };
    let input = match strict_json(&payload.input) {
        Some(JsonValue::Null) | None => {
            return Ok(Err(MeasurementUnavailable::UnsupportedTaskPayload));
        }
        Some(input) => input,
    };
    let text = serde_json::to_vec(&input)
        .map_err(|_| Error::CorruptedIndex("eval measurement task input"))?;
    let source_rows = case.content_source_rows();
    Ok(Ok(EvalTaskInput {
        case: case.id,
        family: case.family,
        stratum: case.stratum,
        kind: payload.attempt_type,
        input,
        labels: case
            .labels
            .into_iter()
            .filter(|label| label.kind.anchors())
            .collect(),
        source_hash: *blake3::hash(&record.payload).as_bytes(),
        task_hash: *blake3::hash(&text).as_bytes(),
        source_rows,
    }))
}

impl Vault {
    /// The task one member of a claimed measurement was given, for the
    /// measuring host alone: the stored claim, its three Candidate
    /// exposures and the cohort's membership are read here, never taken
    /// from the caller. An unreleased case, a moved cohort or an unsupported
    /// task is unavailable, with its reason.
    /// # Errors
    /// A missing measurement, a member gone from the ledger, or storage
    /// errors.
    pub fn released_eval_task(
        &self,
        measurement: &[u8; 32],
        case: &EntityId,
    ) -> Result<std::result::Result<EvalTaskInput, MeasurementUnavailable>> {
        let txn = self.store.env.read_txn()?;
        let row = measurement_in_txn(self, &txn, measurement)?.ok_or(Error::EntityNotFound)?;
        if !released(self, &txn, &row)? || !row.members.contains(case) {
            return Ok(Err(MeasurementUnavailable::NotReleased));
        }
        let cohort = cohort_in_txn(self, &txn, &row.request.cohort)?;
        if cohort.membership_digest != row.request.membership_digest || cohort.cases != row.members
        {
            return Ok(Err(MeasurementUnavailable::CohortMoved));
        }
        let member =
            case_in_txn(self, &txn, case)?.ok_or(Error::CorruptedIndex("eval cohort case"))?;
        hydrate(self, &txn, member)
    }
}
