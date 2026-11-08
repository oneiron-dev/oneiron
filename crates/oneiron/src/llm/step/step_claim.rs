//! Terminal dreamer.step claim write and step-claim codec. The memo index
//! moved to `step_index` (FIX 4816); its names stay reachable here.

use super::super::{CallPurpose, LlmRequest, LlmResponse, canonical_json_bytes};
use super::codec::{
    decode_attempt_id_value, decode_entity_id_value, decode_hash_hex, expect_key, expect_map,
    expect_string, expect_u64, invalid_step, pinned_key_index,
};
use super::response_pins::{StepResponseRef, register_step_response_pin_in_txn};
use super::step_state::{
    StepStateDisposition, StepStateOwners, StepStateRow, step_state_put_in_txn, step_state_read,
};
use super::types::{
    DREAMER_STEP_INLINE_RESPONSE_MAX_BYTES, DREAMER_STEP_PREDICATE, DREAMER_STEP_VALUE_KEYS,
    DREAMER_STEP_VALUE_SCHEMA_VERSION, DurableStepContext, DurableStepError, DurableStepResult,
    ENVELOPE_PROVENANCE_ATTEMPT_KEY, ENVELOPE_PROVENANCE_RUN_KEY, ENVELOPE_PROVENANCE_SURFACE_KEY,
    KEY_AT, KEY_ATTEMPT_ID, KEY_MODEL_ID, KEY_PARAMS_HASH, KEY_PROGRESSION, KEY_PURPOSE,
    KEY_RESPONSE, KEY_RESPONSE_HASH, KEY_RESPONSE_REF, KEY_RESPONSE_VERSION, KEY_SCHEMA_VERSION,
    KEY_STEP_HASH, KEY_USAGE_IN, KEY_USAGE_OUT, StepProgression,
};
use crate::Vault;
use crate::attempt_queue::AttemptId;
use crate::blob_artifact::{BlobArtifactBody, BlobVersionProvenance, encode_blob_artifact_body};
use crate::claim::{ClaimApprovalStatus, ClaimSource, ClaimSubject};
use crate::dreamer_runner::DREAMER_RUNNER_ATTEMPT_KIND;
use crate::dreamer_wake::{StepClaimed, StepTerminal, record_call_terminal_in_txn};
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::error::{Error, Result};
use crate::registry::ENTITY_TYPE_BLOB_ARTIFACT;
use crate::temporal::TimeRange;
use crate::write_envelope::{ClaimCandidate, WriteEnvelope, WriteProvenance};
use rmpv::Value;

pub(super) use super::step_index::{
    STEP_INDEX_CLAIM, STEP_INDEX_FORWARD, StepIndexClaimKey, StepIndexKey, step_index_lookup,
    step_index_lookup_in_txn,
};
pub(crate) use super::step_index::{
    deindex_dreamer_step_claim, forget_step_memo, forget_step_memo_in_txn,
    index_dreamer_step_claim_for_put, terminal_step_identity,
};

// ---------------------------------------------------------------------------
// Terminal step claim (checkpoint-in-append)
// ---------------------------------------------------------------------------
/// Persists the terminal `dreamer.step` claim (checkpoint-in-append).
/// `payload` MUST be the serialized JSON bytes of `response` — the fresh path
/// passes the one serialization it already wrote to the ResponseReceived row;
/// the recovery path passes the row bytes the response was deserialized from,
/// so the durable record carries those bytes verbatim. `terminal` names the
/// wake-observed call the claim closes (DOOR-144), in a savepoint of the same
/// write that never refuses it. `None` when an owner's erase took the
/// response first (FIX 6226): the write checked its owners before anything
/// was filed, keeps the row's erased skeleton, and files nothing. An agent
/// run's step commits only while its machine holds the run (FIX 4747): a
/// stale executor's write files nothing and fails with
/// `Error::AgentRunExecutorMoved`.
pub(super) fn log_terminal_step(
    ctx: &DurableStepContext<'_>,
    step_hash: &[u8; 32],
    request: &LlmRequest,
    response: &LlmResponse,
    payload: &[u8],
    terminal: StepTerminal,
) -> DurableStepResult<Option<EntityId>> {
    let params_hash = request_params_hash(request)?;
    let claim_id = ctx.vault.store.clock.entity_id()?;
    let occurred = TimeRange {
        start: ctx.now_ms,
        end: ctx.now_ms,
    };
    let envelope = dreamer_runtime_envelope(ctx)?;
    let inline = payload.len() <= DREAMER_STEP_INLINE_RESPONSE_MAX_BYTES;
    let inline_response = if inline {
        Some(String::from_utf8(payload.to_vec()).map_err(|_| {
            Error::InvalidClaimBody("dreamer step response encoding must be UTF-8 JSON")
        })?)
    } else {
        None
    };
    let existing_started_at = step_state_read(ctx.vault, ctx.attempt_id, step_hash)?
        .map_or(ctx.now_ms, |row| row.started_at);

    ctx.vault
        .with_write_txn_grouped(|wtxn| {
            // FIX 4747: the run fence first, in this same write; it renews
            // the run's executor lease when less than half a hold is left.
            crate::agent_dispatch::fence_agent_run_step_in_txn(ctx.vault, wtxn, ctx.attempt_id)?;
            // The Logged private row lands first, its owners checked in this
            // same write (FIX 6226): an erase that took an owner after the
            // answer came keeps the row's skeleton, and no response, artifact
            // or claim is filed. The batch put hook below indexes the claim
            // in the SAME wtxn, so a death here recovers from either side.
            let logged = step_state_put_in_txn(
                ctx.vault,
                wtxn,
                ctx.attempt_id,
                step_hash,
                &StepStateRow {
                    progression: StepProgression::Logged,
                    started_at: existing_started_at,
                    updated_at: ctx.now_ms,
                    response_payload: Some(payload.to_vec()),
                    owners: StepStateOwners {
                        claim: Some(claim_id),
                        ..StepStateOwners::of(ctx)
                    },
                    erased: false,
                },
            )?;
            if logged == StepStateDisposition::Erased {
                return Ok(None);
            }
            // The step's kept requests stamp the claim in this same write
            // (FIX 6659): the executor deletes the row that names it once
            // the step is done, and an erase of the claim still takes them.
            crate::self_heal::blocked_reports::bind_step_claim_in_txn(
                ctx.vault,
                wtxn,
                ctx.attempt_id,
                step_hash,
                claim_id,
            )?;
            let response_ref = if inline {
                None
            } else {
                let artifact_id = ctx.vault.store.clock.entity_id()?;
                let body = BlobArtifactBody::new("dreamer.step.response", "application/json");
                let encoded = encode_blob_artifact_body(&body)?;
                ctx.vault
                    .batch_in()
                    .put(
                        &artifact_id,
                        ENTITY_TYPE_BLOB_ARTIFACT,
                        occurred,
                        ctx.now_ms,
                        &encoded,
                    )
                    .apply(wtxn)?;
                let run_ref = format!(
                    "dreamer-step:{}",
                    bytes_to_hex_lower(ctx.attempt_id.as_bytes())
                );
                let appended = ctx.vault.append_blob_artifact_version_in_txn(
                    wtxn,
                    &artifact_id,
                    payload,
                    &BlobVersionProvenance::AgentRun { run_ref },
                    ctx.envelope_actor,
                    occurred,
                    ctx.now_ms,
                )?;
                Some(StepResponseRef {
                    artifact_id,
                    version: appended.version,
                    content_hash: appended.content_hash,
                })
            };

            let value = encode_step_claim_value(&EncodedStepClaim {
                attempt_id: ctx.attempt_id,
                step_hash: *step_hash,
                progression: StepProgression::Finished,
                model_id: request.model.as_str().to_owned(),
                purpose: call_purpose_str(&request.envelope.purpose),
                params_hash: params_hash.clone(),
                usage_in: response.usage.input.total,
                usage_out: response.usage.output.total,
                response: inline_response.clone(),
                response_ref,
                at: ctx.now_ms,
            });
            let candidate = ClaimCandidate::new(
                DREAMER_STEP_PREDICATE,
                ClaimSubject::Entity(ctx.subject),
                value,
                1.0,
            );
            let mut envelope = envelope.clone();
            ctx.vault.sign_retained_machine_claim_in_txn(
                &*wtxn,
                &claim_id,
                &candidate,
                &mut envelope,
            )?;
            ctx.vault
                .batch_in()
                .claim_candidate(&claim_id, candidate, &envelope, occurred, ctx.now_ms)
                .apply(wtxn)?;
            // The claim holds the exact version its response lives in, so
            // its erase reaches that version (FIX 6225).
            if let Some(pin) = &response_ref {
                register_step_response_pin_in_txn(&ctx.vault.store, wtxn, &claim_id, pin)?;
            }
            let claimed = StepClaimed {
                attempt_id: ctx.attempt_id,
                step_hash: *step_hash,
                claim: claim_id,
                used_units: response
                    .usage
                    .input
                    .total
                    .saturating_add(response.usage.output.total),
                terminal,
            };
            record_call_terminal_in_txn(ctx.vault, wtxn, &claimed);
            Ok(Some(claim_id))
        })
        .map_err(DurableStepError::from)
}

pub(super) fn load_step_response(
    vault: &Vault,
    decoded: &DecodedStepClaim,
) -> DurableStepResult<LlmResponse> {
    let txn = vault.store.env.read_txn().map_err(Error::from)?;
    load_step_response_in_txn(vault, &txn, decoded)
}

pub(super) fn load_step_response_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    decoded: &DecodedStepClaim,
) -> DurableStepResult<LlmResponse> {
    match (&decoded.response, &decoded.response_ref) {
        (Some(inline), None) => Ok(serde_json::from_slice(inline.as_bytes())?),
        (None, Some(response_ref)) => {
            // The version the step appended, never the artifact's head: a
            // later append to the same artifact is not this step's response.
            let bytes = vault
                .read_blob_artifact_version_in_txn(
                    txn,
                    &response_ref.artifact_id,
                    response_ref.version,
                )?
                .ok_or(Error::InvalidClaimBody(
                    "dreamer step response_ref version missing",
                ))?;
            if *blake3::hash(&bytes).as_bytes() != response_ref.content_hash {
                return Err(Error::InvalidClaimBody(
                    "dreamer step response_ref content does not match its pin",
                )
                .into());
            }
            Ok(serde_json::from_slice(&bytes)?)
        }
        // decode_step_claim_value already fail-closes; defensive here.
        _ => Err(Error::InvalidClaimBody("dreamer step claim response shape invalid").into()),
    }
}

/// The WITH-WHAT params identity: BLAKE3 of the request's canonical params
/// JSON, lowercase hex. The terminal claim writer and the memo-hit provenance
/// check MUST agree byte-for-byte, so both go through this one helper.
pub(super) fn request_params_hash(request: &LlmRequest) -> DurableStepResult<String> {
    Ok(bytes_to_hex_lower(
        blake3::hash(&canonical_json_bytes(&request.params)?).as_bytes(),
    ))
}

/// True iff a stored terminal `dreamer.step` claim was recorded for exactly
/// this request's model/purpose/params identity. Used by the memo-hit branch:
/// a `false` here is a MISS (recompute), never a returned foreign response.
pub(super) fn step_claim_matches_request(
    decoded: &DecodedStepClaim,
    request: &LlmRequest,
) -> DurableStepResult<bool> {
    Ok(decoded.model_id == request.model.as_str()
        && decoded.purpose == call_purpose_str(&request.envelope.purpose)
        && decoded.params_hash == request_params_hash(request)?)
}

pub(super) fn call_purpose_str(purpose: &CallPurpose) -> String {
    match purpose {
        CallPurpose::Extraction => "extraction".to_owned(),
        CallPurpose::Consolidation => "consolidation".to_owned(),
        CallPurpose::AnswerGen => "answer_gen".to_owned(),
        CallPurpose::AutoCheck => "auto_check".to_owned(),
        CallPurpose::ToolRouting => "tool_routing".to_owned(),
        CallPurpose::Voice => "voice".to_owned(),
        CallPurpose::Eval => "eval".to_owned(),
        CallPurpose::AutonomyForHuman => "autonomy.for_human".to_owned(),
        CallPurpose::AutonomyOwnTime => "autonomy.own_time".to_owned(),
        CallPurpose::Other { name } => format!("other:{name}"),
    }
}

pub(super) fn dreamer_runtime_envelope(ctx: &DurableStepContext<'_>) -> Result<WriteEnvelope> {
    let mut entries = vec![(
        Value::from(ENVELOPE_PROVENANCE_SURFACE_KEY),
        Value::from(DREAMER_RUNNER_ATTEMPT_KIND),
    )];
    if let Some(run_id) = &ctx.run_id {
        entries.push((
            Value::from(ENVELOPE_PROVENANCE_RUN_KEY),
            Value::from(run_id.as_str()),
        ));
    }
    entries.push((
        Value::from(ENVELOPE_PROVENANCE_ATTEMPT_KEY),
        Value::from(bytes_to_hex_lower(ctx.attempt_id.as_bytes())),
    ));
    Ok(WriteEnvelope::new(
        ctx.envelope_actor,
        ClaimSource::Generated,
        WriteProvenance::new(Value::Map(entries))?,
        ClaimApprovalStatus::Proposed,
    ))
}

pub(super) struct EncodedStepClaim {
    pub(super) attempt_id: AttemptId,
    pub(super) step_hash: [u8; 32],
    pub(super) progression: StepProgression,
    pub(super) model_id: String,
    pub(super) purpose: String,
    pub(super) params_hash: String,
    pub(super) usage_in: u64,
    pub(super) usage_out: u64,
    pub(super) response: Option<String>,
    pub(super) response_ref: Option<StepResponseRef>,
    pub(super) at: u64,
}

pub(super) fn encode_step_claim_value(claim: &EncodedStepClaim) -> Value {
    let mut entries = vec![
        (
            Value::from(KEY_SCHEMA_VERSION),
            Value::from(DREAMER_STEP_VALUE_SCHEMA_VERSION),
        ),
        (
            Value::from(KEY_ATTEMPT_ID),
            Value::Binary(claim.attempt_id.as_bytes().to_vec()),
        ),
        (
            Value::from(KEY_STEP_HASH),
            Value::from(bytes_to_hex_lower(&claim.step_hash)),
        ),
        (
            Value::from(KEY_PROGRESSION),
            Value::from(claim.progression.as_str()),
        ),
        (
            Value::from(KEY_MODEL_ID),
            Value::from(claim.model_id.as_str()),
        ),
        (
            Value::from(KEY_PURPOSE),
            Value::from(claim.purpose.as_str()),
        ),
        (
            Value::from(KEY_PARAMS_HASH),
            Value::from(claim.params_hash.as_str()),
        ),
        (Value::from(KEY_USAGE_IN), Value::from(claim.usage_in)),
        (Value::from(KEY_USAGE_OUT), Value::from(claim.usage_out)),
    ];
    if let Some(response) = &claim.response {
        entries.push((Value::from(KEY_RESPONSE), Value::from(response.as_str())));
    }
    if let Some(response_ref) = &claim.response_ref {
        entries.push((
            Value::from(KEY_RESPONSE_REF),
            Value::Binary(response_ref.artifact_id.as_bytes().to_vec()),
        ));
        entries.push((
            Value::from(KEY_RESPONSE_VERSION),
            Value::from(response_ref.version),
        ));
        entries.push((
            Value::from(KEY_RESPONSE_HASH),
            Value::Binary(response_ref.content_hash.to_vec()),
        ));
    }
    entries.push((Value::from(KEY_AT), Value::from(claim.at)));
    Value::Map(entries)
}

/// Consumed fields of a decoded `dreamer.step` claim value. The decoder
/// validates EVERY pinned key fail-closed and stores what production readers
/// use: the memo-index key pair, the response location, and the WITH-WHAT
/// provenance triple the memo-hit check and the index admission gate compare
/// against the live request (ONE-1344).
pub(super) struct DecodedStepClaim {
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
}

/// Fail-closed `dreamer.step` claim value decode: pinned keys only, no
/// duplicates, schema-version checked, and EXACTLY ONE of
/// `response`/`response_ref` present (both or neither is a typed error).
pub(super) fn decode_step_claim_value(value: &Value) -> Result<DecodedStepClaim> {
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
    })
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
