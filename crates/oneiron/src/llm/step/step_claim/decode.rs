//! The fail-closed decode of a `dreamer.step` claim value and the fields its readers consume.

use super::super::codec::{
    decode_attempt_id_value, decode_entity_id_value, decode_hash_hex, expect_key, expect_map,
    expect_string, expect_u64, invalid_step, pinned_key_index,
};
use super::super::request_hash_step::{StepInputLabels, StepInputRange};
use super::super::response_pins::StepResponseRef;
use super::super::types::{
    DREAMER_STEP_VALUE_KEYS, DREAMER_STEP_VALUE_SCHEMA_VERSION, KEY_AT, KEY_ATTEMPT_ID,
    KEY_INPUT_LABELS, KEY_INPUT_RANGES, KEY_INPUT_SLICE, KEY_INPUT_SOURCES, KEY_INPUT_VERSIONS,
    KEY_MODEL_ID, KEY_PARAMS_HASH, KEY_PROGRESSION, KEY_PURPOSE, KEY_RESPONSE, KEY_RESPONSE_HASH,
    KEY_RESPONSE_REF, KEY_RESPONSE_VERSION, KEY_SCHEMA_VERSION, KEY_STEP_HASH, KEY_USAGE_IN,
    KEY_USAGE_OUT, StepProgression,
};
use crate::attempt_queue::AttemptId;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::snapshot_read::SourceVersion;
use rmpv::Value;

/// Consumed fields of a decoded `dreamer.step` claim value. The decoder
/// validates EVERY pinned key fail-closed and stores what production readers
/// use: the memo-index key pair, the response location, and the WITH-WHAT
/// provenance triple the memo-hit check and the index admission gate compare
/// against the live request (ONE-1344).
pub(in crate::llm::step) struct DecodedStepClaim {
    pub(crate) attempt_id: AttemptId,
    pub(crate) step_hash: [u8; 32],
    pub(crate) model_id: String,
    pub(crate) purpose: String,
    pub(crate) params_hash: String,
    // Usage totals are an audit surface on the durable record; no production
    // reader consumes them yet.
    #[allow(dead_code)]
    pub(crate) usage_in: u64,
    #[allow(dead_code)]
    pub(crate) usage_out: u64,
    pub(crate) response: Option<String>,
    pub(crate) response_ref: Option<StepResponseRef>,
    /// The version of every source row a bound step's request was read from;
    /// `None` for a step that names none.
    pub(crate) input_versions: Option<Vec<SourceVersion>>,
    /// The row behind each call label of a bound step's call; `None` for a
    /// step that names none.
    pub(crate) input_labels: Option<StepInputLabels>,
    /// The shown range of each cited TURN of a bound step's call, in request
    /// order; `None` for a step that names none.
    pub(crate) input_ranges: Option<Vec<StepInputRange>>,
    /// The listed entities of a bound step's native slice; `None` for a step
    /// that names none.
    pub(crate) input_slice: Option<Vec<EntityId>>,
}

/// Fail-closed `dreamer.step` claim value decode: pinned keys only, no
/// duplicates, schema-version checked, and EXACTLY ONE of
/// `response`/`response_ref` present (both or neither is a typed error). The
/// source rows a bound step names are checked as their fact and not kept here:
/// no reader of this decode consumes them.
pub(in crate::llm::step) fn decode_step_claim_value(value: &Value) -> Result<DecodedStepClaim> {
    let entries = expect_map(value, "dreamer step value must be a MessagePack map")?;
    let mut schema_version = None;
    let mut attempt_id = None;
    let mut step_hash = None;
    let mut progression = None;
    let mut model_id = None;
    let mut purpose = None;
    let mut params_hash = None;
    let mut usage_in = None;
    let mut usage_out = None;
    let mut response = None;
    let mut response_ref = None;
    let mut response_version = None;
    let mut response_hash = None;
    let mut at = None;
    let mut input_versions = None;
    let mut input_labels = None;
    let mut input_ranges = None;
    let mut input_slice = None;
    let mut seen = [false; DREAMER_STEP_VALUE_KEYS.len()];

    for (key, value) in entries {
        let key = expect_key(key, "dreamer step value keys must be strings")?;
        let index = pinned_key_index(key, &DREAMER_STEP_VALUE_KEYS)
            .ok_or(invalid_step("dreamer step value key is not pinned"))?;
        if seen[index] {
            return Err(invalid_step("duplicate dreamer step value key"));
        }
        seen[index] = true;

        match DREAMER_STEP_VALUE_KEYS[index] {
            KEY_SCHEMA_VERSION => {
                schema_version = Some(expect_u64(
                    value,
                    "dreamer step value schema_version must be an integer",
                )?);
            }
            KEY_ATTEMPT_ID => attempt_id = Some(decode_attempt_id_value(value)?),
            KEY_STEP_HASH => {
                let hex = expect_string(value, "dreamer step value step_hash must be a string")?;
                step_hash = Some(decode_hash_hex(&hex)?);
            }
            KEY_PROGRESSION => {
                let parsed =
                    expect_string(value, "dreamer step value progression must be a string")?;
                progression = Some(parse_progression_str(&parsed)?);
            }
            KEY_MODEL_ID => {
                model_id = Some(expect_string(
                    value,
                    "dreamer step value model_id must be a string",
                )?);
            }
            KEY_PURPOSE => {
                purpose = Some(expect_string(
                    value,
                    "dreamer step value purpose must be a string",
                )?);
            }
            KEY_PARAMS_HASH => {
                params_hash = Some(expect_string(
                    value,
                    "dreamer step value params_hash must be a string",
                )?);
            }
            KEY_USAGE_IN => {
                usage_in = Some(expect_u64(
                    value,
                    "dreamer step value usage_in must be an integer",
                )?);
            }
            KEY_USAGE_OUT => {
                usage_out = Some(expect_u64(
                    value,
                    "dreamer step value usage_out must be an integer",
                )?);
            }
            KEY_RESPONSE => {
                response = Some(expect_string(
                    value,
                    "dreamer step value response must be a string",
                )?);
            }
            KEY_RESPONSE_REF => response_ref = Some(decode_entity_id_value(value)?),
            KEY_RESPONSE_VERSION => {
                response_version = Some(expect_u64(
                    value,
                    "dreamer step value response_version must be an integer",
                )?);
            }
            KEY_RESPONSE_HASH => {
                let Value::Binary(bytes) = value else {
                    return Err(invalid_step("dreamer step response_hash must be binary"));
                };
                response_hash =
                    Some(<[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| {
                        invalid_step("dreamer step response_hash must be 32 bytes")
                    })?);
            }
            KEY_AT => {
                at = Some(expect_u64(
                    value,
                    "dreamer step value at must be an integer",
                )?);
            }
            KEY_INPUT_VERSIONS => {
                let encoded =
                    expect_string(value, "dreamer step value input_versions must be a string")?;
                input_versions = Some(serde_json::from_str(&encoded).map_err(|_| {
                    invalid_step("dreamer step value input_versions must list source versions")
                })?);
            }
            KEY_INPUT_LABELS => {
                input_labels = Some(json_fact::<StepInputLabels>(
                    value,
                    "dreamer step value input_labels must be a string",
                    "dreamer step value input_labels must list each label prefix's rows",
                )?);
            }
            KEY_INPUT_RANGES => {
                input_ranges = Some(json_fact::<Vec<StepInputRange>>(
                    value,
                    "dreamer step value input_ranges must be a string",
                    "dreamer step value input_ranges must list TURN ranges",
                )?);
            }
            KEY_INPUT_SOURCES => {
                json_fact::<Vec<EntityId>>(
                    value,
                    "dreamer step value input_sources must be a string",
                    "dreamer step value input_sources must list source rows",
                )?;
            }
            KEY_INPUT_SLICE => {
                input_slice = Some(json_fact::<Vec<EntityId>>(
                    value,
                    "dreamer step value input_slice must be a string",
                    "dreamer step value input_slice must list entities",
                )?);
            }
            _ => unreachable!("index resolved from DREAMER_STEP_VALUE_KEYS"),
        }
    }

    let schema_version =
        schema_version.ok_or(invalid_step("missing dreamer step value schema_version"))?;
    if schema_version != DREAMER_STEP_VALUE_SCHEMA_VERSION {
        return Err(invalid_step(
            "unsupported dreamer step value schema_version",
        ));
    }
    let response_ref = match (response_ref, response_version, response_hash) {
        (Some(artifact_id), Some(version), Some(content_hash)) => Some(StepResponseRef {
            artifact_id,
            version,
            content_hash,
        }),
        (None, None, None) => None,
        _ => {
            return Err(invalid_step(
                "dreamer step response_ref must carry its version and content hash",
            ));
        }
    };
    if response.is_some() == response_ref.is_some() {
        return Err(invalid_step(
            "dreamer step value must carry exactly one of response/response_ref",
        ));
    }

    progression.ok_or(invalid_step("missing dreamer step value progression"))?;
    let model_id = model_id.ok_or(invalid_step("missing dreamer step value model_id"))?;
    let purpose = purpose.ok_or(invalid_step("missing dreamer step value purpose"))?;
    let params_hash = params_hash.ok_or(invalid_step("missing dreamer step value params_hash"))?;
    let usage_in = usage_in.ok_or(invalid_step("missing dreamer step value usage_in"))?;
    let usage_out = usage_out.ok_or(invalid_step("missing dreamer step value usage_out"))?;
    at.ok_or(invalid_step("missing dreamer step value at"))?;

    Ok(DecodedStepClaim {
        attempt_id: attempt_id.ok_or(invalid_step("missing dreamer step value job_id"))?,
        step_hash: step_hash.ok_or(invalid_step("missing dreamer step value step_hash"))?,
        model_id,
        purpose,
        params_hash,
        usage_in,
        usage_out,
        response,
        response_ref,
        input_versions,
        input_labels,
        input_ranges,
        input_slice,
    })
}

/// Reads `value`, one JSON string, as a `T`.
fn json_fact<T: serde::de::DeserializeOwned>(
    value: &Value,
    not_string: &'static str,
    not_fact: &'static str,
) -> Result<T> {
    let encoded = expect_string(value, not_string)?;
    serde_json::from_str(&encoded).map_err(|_| invalid_step(not_fact))
}

fn parse_progression_str(value: &str) -> Result<StepProgression> {
    match value {
        "started" => Ok(StepProgression::Started),
        "response_received" => Ok(StepProgression::ResponseReceived),
        "logged" => Ok(StepProgression::Logged),
        "finished" => Ok(StepProgression::Finished),
        _ => Err(invalid_step("unknown dreamer step value progression")),
    }
}
