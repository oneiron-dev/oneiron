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
use super::repair_seed::{grade, memory_read_refused, row_reads_in_txn};
use super::{
    DerivationKind, EvalCase, EvalExposureKind, EvalLabel, EvalRepairLegAnswer, EvalRepairSeed,
    EvalRepairSeedState, EvalRepairTask, case_in_txn,
};
use crate::EdgeActorClass;
use crate::Vault;
use crate::attempt_queue::{AttemptId, AttemptQueue};
use crate::dreamer_runner::decode_dreamer_attempt_payload;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::ingest::ag_ui_capture_owner_in_txn;

/// A terminal pack receipt's namespace: `attempt:<32 hex>`.
const ATTEMPT_RECEIPT: &str = "attempt:";

/// `EvalTaskInput.kind` of a released Repair case.
pub const REPAIR_RESPONSE_TASK_KIND: &str = "repair_response";

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
    /// against. None for a Repair case, which fixed code grades.
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

/// One attempt case's task input as comparison text, for the cut audit's
/// comparison alone (FIX 3639, FIX 10440): the kept attempt's input
/// rendered as JSON text, with its row id for the listing. `None` for every
/// other shape — a non-attempt case, a gone attempt, an undecodable
/// payload — a gap, never an error. It grants no measurement: the measuring
/// host's gate stays on [`Vault::released_eval_task`]. Comparison text and
/// the attempt id only, never the structured input, labels, hashes or kind.
pub(super) fn cut_audit_task_text_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    receipts: &[String],
    parents: &[EntityId],
) -> Result<Option<(EntityId, String)>> {
    let [receipt] = receipts else {
        return Ok(None);
    };
    if !parents.is_empty() {
        return Ok(None);
    }
    let Some(hex) = receipt.strip_prefix(ATTEMPT_RECEIPT) else {
        return Ok(None);
    };
    let Ok(id) = EntityId::from_hex(hex) else {
        return Ok(None);
    };
    let Ok(attempt) = AttemptId::from_bytes(id.as_bytes()) else {
        return Ok(None);
    };
    let Some(record) = AttemptQueue::new(vault).get_in_txn(txn, attempt)? else {
        return Ok(None);
    };
    let Ok(payload) = decode_dreamer_attempt_payload(&record.payload) else {
        return Ok(None);
    };
    let Some(input) = strict_json(&payload.input) else {
        return Ok(None);
    };
    if matches!(input, JsonValue::Null) {
        return Ok(None);
    }
    let Ok(text) = serde_json::to_string(&input) else {
        return Ok(None);
    };
    Ok(Some((id, text)))
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

/// A released Repair case: its recompiled task, the `Confirmed` seed
/// holding it, and its ledger row, after every release check.
struct ReleasedRepair {
    task: EvalRepairTask,
    seed: EvalRepairSeed,
    member: EvalCase,
}

/// A Repair member's release, for [`Vault::released_eval_task`] and
/// [`Vault::grade_released_eval_repair_answer`] alike: the claimed
/// measurement's checks, the case index's `Confirmed` seed, then the task
/// recompiled through the capture owner's own scoped read.
fn released_repair_task(
    vault: &Vault,
    measurement: &[u8; 32],
    case: &EntityId,
) -> Result<std::result::Result<ReleasedRepair, MeasurementUnavailable>> {
    let txn = vault.store.env.read_txn()?;
    let row = measurement_in_txn(vault, &txn, measurement)?.ok_or(Error::EntityNotFound)?;
    if !released(vault, &txn, &row)? || !row.members.contains(case) {
        return Ok(Err(MeasurementUnavailable::NotReleased));
    }
    let cohort = cohort_in_txn(vault, &txn, &row.request.cohort)?;
    if cohort.membership_digest != row.request.membership_digest || cohort.cases != row.members {
        return Ok(Err(MeasurementUnavailable::CohortMoved));
    }
    let member =
        case_in_txn(vault, &txn, case)?.ok_or(Error::CorruptedIndex("eval cohort case"))?;
    if member.kind != DerivationKind::Repair {
        return Ok(Err(MeasurementUnavailable::UnsupportedTaskPayload));
    }
    let Some(seed) = vault.eval_repair_seed_for_case_in_txn(&txn, &member.id)? else {
        return Ok(Err(MeasurementUnavailable::UnsupportedTaskPayload));
    };
    let confirmed = matches!(
        &seed.state,
        EvalRepairSeedState::Confirmed { case: held, .. } if held == &member.id
    );
    if !confirmed {
        return Ok(Err(MeasurementUnavailable::UnsupportedTaskPayload));
    }
    for row in &seed.source_rows {
        if !row_reads_in_txn(vault, &txn, row)? {
            return Ok(Err(MeasurementUnavailable::TaskGone));
        }
    }
    let Ok(claim) = EntityId::from_hex(&seed.source.claim_ref) else {
        return Ok(Err(MeasurementUnavailable::TaskGone));
    };
    let owner = ag_ui_capture_owner_in_txn(vault, &txn, &claim)?;
    drop(txn);
    let Some(owner) = owner else {
        return Ok(Err(MeasurementUnavailable::TaskGone));
    };
    let read = match vault
        .memory(owner, EdgeActorClass::Human)
        .read_eval_repair_task(&seed.source)
    {
        Ok(read) => read,
        Err(error) if memory_read_refused(&error) => {
            return Ok(Err(MeasurementUnavailable::TaskGone));
        }
        Err(error) => return Err(Error::Refused(error.message)),
    };
    let Some(mut task) = read.task else {
        return Ok(Err(MeasurementUnavailable::TaskGone));
    };
    if let Some(adjudication) = &seed.adjudication {
        task.adjudicate(adjudication.answer_digest);
    }
    if task.task_hash != seed.task_hash {
        return Ok(Err(MeasurementUnavailable::TaskGone));
    }
    Ok(Ok(ReleasedRepair { task, seed, member }))
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
        if member.kind == DerivationKind::Repair {
            // The Repair path reads on its own snapshot, then through the
            // capture owner's scoped read: no second reader on this thread.
            drop(txn);
            let released = released_repair_task(self, measurement, case)?;
            let repair = match released {
                Err(unavailable) => return Ok(Err(unavailable)),
                Ok(repair) => repair,
            };
            let source_hash: [u8; 32] = oneiron_hex::decode(&repair.seed.source.source_hash)
                .ok_or(Error::CorruptedIndex("eval repair seed source hash"))?;
            // The leg input, with the declared tools materialized for the
            // call: the task's `tools` field holds their names, and the
            // server parses the declared tools from here.
            let mut input = repair.task.response_input().clone();
            if let Some(fields) = input.as_object_mut() {
                fields.insert(
                    "tools".to_owned(),
                    serde_json::to_value(repair.task.tools())
                        .map_err(|_| Error::CorruptedIndex("eval measurement task input"))?,
                );
            }
            return Ok(Ok(EvalTaskInput {
                case: repair.member.id,
                family: repair.member.family,
                stratum: repair.member.stratum.clone(),
                kind: REPAIR_RESPONSE_TASK_KIND.to_owned(),
                input,
                // Fixed code grades a Repair case
                // (`grade_released_eval_repair_answer`), so the host is
                // handed no label: each holds the outcome's digest.
                labels: Vec::new(),
                source_hash,
                task_hash: repair.seed.task_hash,
                source_rows: repair.member.content_source_rows(),
            }));
        }
        hydrate(self, &txn, member)
    }

    /// Fixed code's exact grade of one leg's answer on a released Repair case of a claimed measurement: the same
    /// release checks as `released_eval_task`, then the recompiled task's `grade_response` / `grade_tool_calls`.
    /// `Err(UnsupportedTaskPayload)` for a case no Confirmed seed holds; `Err(TaskGone)` for a capture that no longer
    /// reads or a task that moved.
    /// # Errors
    /// A missing measurement, a member gone from the ledger, or storage
    /// errors.
    pub fn grade_released_eval_repair_answer(
        &self,
        measurement: &[u8; 32],
        case: &EntityId,
        answer: &EvalRepairLegAnswer,
    ) -> Result<std::result::Result<bool, MeasurementUnavailable>> {
        let released = released_repair_task(self, measurement, case)?;
        let repair = match released {
            Err(unavailable) => return Ok(Err(unavailable)),
            Ok(repair) => repair,
        };
        Ok(Ok(grade(&repair.task, answer)))
    }
}
