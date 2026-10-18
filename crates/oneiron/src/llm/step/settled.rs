//! Settled-step point read (DOOR-141 A): one committed model step of a
//! Dreamer attempt, as its terminal `dreamer.step` claim recorded it. It
//! executes nothing, admits nothing and spends no lease; a step with no
//! completion claim reads as absent, never as a success synthesized from a
//! live progression row or a completed queue row.
use serde::{Deserialize, Serialize};

use super::super::{LlmResponse, ModelId};
use super::codec::decode_hash_hex;
use super::step_claim::{
    DecodedStepClaim, decode_step_claim_value, load_step_response_in_txn, step_index_lookup_in_txn,
    terminal_step_identity,
};
use super::types::{DurableStepError, ENVELOPE_PROVENANCE_RUN_KEY};
use crate::attempt_queue::AttemptId;
use crate::claim::ClaimBody;
use crate::consent::AuthenticatedOwner;
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::error::Error;
use crate::memory::{MEMORY_CODE_FORBIDDEN, Memory, MemoryError, MemoryResult};
use crate::write_envelope::WRITE_ENVELOPE_EVIDENCE_PROVENANCE_KEY;

/// One step of one attempt, by the attempt's job ref and the step's
/// canonical request hash.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SettledStepRequest {
    /// 32-hex attempt id (`job:` prefix allowed), as the consolidation
    /// status read names it.
    pub job_ref: String,
    /// 64-hex canonical request hash of the step.
    pub step_hash: String,
}

/// A committed model step: the completion claim, the identity it was
/// recorded for, and the stored response it settled with.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SettledStepView {
    /// 32-hex attempt id.
    pub job_ref: String,
    /// The run correlation id the completion claim's write envelope
    /// recorded at the step's commit; absent when the attempt had none.
    pub run_id: Option<String>,
    /// 32-hex id of the terminal `dreamer.step` claim.
    pub claim_ref: String,
    /// 64-hex canonical request hash.
    pub step_hash: String,
    /// The fully revisioned model the step was recorded for.
    pub model: ModelId,
    /// The call purpose the step was recorded for.
    pub purpose: String,
    /// BLAKE3 of the request's canonical params JSON, lowercase hex.
    pub params_hash: String,
    /// The stored response: inline, or the exact artifact version the
    /// step appended, checked against its pin.
    pub response: LlmResponse,
}

/// Reads one settled step for the vault's owner. The completion claim and
/// any response artifact it pins are read through `memory`'s own read lane
/// and locality, and listed as the answer's producers, before any byte is
/// returned.
pub fn settled_step_as_owner(
    memory: &Memory<'_>,
    owner: &AuthenticatedOwner,
    input: &SettledStepRequest,
) -> MemoryResult<Option<SettledStepView>> {
    let vault = memory.vault();
    owner.revalidate(vault)?;
    let attempt = attempt_ref(&input.job_ref)?;
    let step_hash = decode_hash_hex(input.step_hash.trim())
        .map_err(|_| MemoryError::bad_request("step_hash must be 64 hex characters"))?;
    // One snapshot: the memo-index target, its claim and its response.
    let txn = vault.store.env.read_txn().map_err(Error::from)?;
    let Some(claim_id) = step_index_lookup_in_txn(vault, &txn, attempt, &step_hash)? else {
        return Ok(None);
    };
    let Some(body) = vault.get_claim_in_txn(&txn, &claim_id)? else {
        return Ok(None);
    };
    // Terminal-step binding and Finished only: the claim must be the
    // runner's own record of exactly this attempt's step.
    let Some((bound_attempt, bound_hash, model)) = terminal_step_identity(&body) else {
        return Ok(None);
    };
    if bound_attempt != attempt || bound_hash != step_hash {
        return Ok(None);
    }
    let decoded = decode_step_claim_value(&body.value)?;
    let response = load_step_response_in_txn(vault, &txn, &decoded).map_err(step_error)?;
    drop(txn);
    let mut sources = vec![claim_id];
    sources.extend(response_artifact(&decoded));
    readable(memory, &sources)?;
    Ok(Some(SettledStepView {
        job_ref: bytes_to_hex_lower(attempt.as_bytes()),
        run_id: recorded_run_id(&body),
        claim_ref: claim_id.to_hex(),
        step_hash: bytes_to_hex_lower(&step_hash),
        model,
        purpose: decoded.purpose,
        params_hash: decoded.params_hash,
        response,
    }))
}

fn attempt_ref(job_ref: &str) -> MemoryResult<AttemptId> {
    let text = job_ref.trim();
    let text = text.strip_prefix("job:").unwrap_or(text);
    let id = EntityId::from_hex(text)
        .map_err(|_| MemoryError::bad_request("job_ref must be a 32-hex attempt id"))?;
    Ok(AttemptId::from_bytes(id.as_bytes())?)
}

fn response_artifact(decoded: &DecodedStepClaim) -> Option<EntityId> {
    decoded.response_ref.map(|pin| pin.artifact_id)
}

/// Every row the answer derives from must read on this credential; each
/// read lists it as a producer at the handle's locality.
fn readable(memory: &Memory<'_>, rows: &[EntityId]) -> MemoryResult<()> {
    for row in rows {
        if memory.get_entity(&row.to_hex())?.value.is_none() {
            return Err(MemoryError::new(
                MEMORY_CODE_FORBIDDEN,
                "a settled step's record is not readable on this credential",
                &[],
            ));
        }
    }
    Ok(())
}

/// The run id the claim's stamped write-envelope provenance carries: the
/// step's original run, never one the read supplies.
fn recorded_run_id(body: &ClaimBody) -> Option<String> {
    let rmpv::Value::Map(evidence) = body.evidence.as_ref()? else {
        return None;
    };
    let provenance = evidence.iter().find_map(|(key, value)| {
        (key.as_str() == Some(WRITE_ENVELOPE_EVIDENCE_PROVENANCE_KEY)).then_some(value)
    });
    let Some(rmpv::Value::Map(entries)) = provenance else {
        return None;
    };
    entries
        .iter()
        .find(|(key, _)| key.as_str() == Some(ENVELOPE_PROVENANCE_RUN_KEY))
        .and_then(|(_, value)| value.as_str())
        .map(str::to_owned)
}

fn step_error(error: DurableStepError) -> MemoryError {
    match error {
        DurableStepError::Engine(error) => error.into(),
        _ => Error::InvalidClaimBody("dreamer step response did not decode").into(),
    }
}
