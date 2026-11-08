//! Settled-step point read (DOOR-141 A): one committed model step of a
//! Dreamer attempt, as its terminal `dreamer.step` claim recorded it; and
//! a page of one attempt's committed step refs (DOOR-101). Neither
//! executes, admits or spends a lease; a step with no completion claim
//! reads as absent, never as a success synthesized from a live progression
//! row or a completed queue row. A self-written compaction's filed step
//! reads the same way, by the job it was filed under (FIX 4816).
use std::ops::Bound;

pub use crate::model_step_record::{SettledStepRequest, SettledStepView};

use super::super::{LlmResponse, LlmUsage};
use super::codec::decode_hash_hex;
use super::step_claim::{
    DecodedStepClaim, STEP_INDEX_FORWARD, StepIndexKey, decode_step_claim_value,
    load_step_response_in_txn, step_index_lookup_in_txn, terminal_step_identity,
};
use super::step_index::step_claim_is_runner_execution;
use super::types::{DurableStepError, ENVELOPE_PROVENANCE_RUN_KEY};
use crate::Vault;
use crate::attempt_queue::AttemptId;
use crate::claim::ClaimBody;
use crate::consent::AuthenticatedOwner;
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::error::Error;
use crate::memory::{MEMORY_CODE_FORBIDDEN, Memory, MemoryError, MemoryResult};
use crate::write_envelope::WRITE_ENVELOPE_EVIDENCE_PROVENANCE_KEY;

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
    // Terminal-step binding and Finished only: the claim must be its
    // producer's own record of exactly this job's step (FIX 4816).
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

pub(crate) use crate::model_step_record::CallerSettledStep;

/// Reads one settled step of `attempt` for `memory`'s own caller, with no
/// owner proof (DOOR-141 PR3a): the terminal claim and any response artifact
/// it pins must read on the caller's own lane and locality, each listed as a
/// producer, or the step reads as withheld and no response is loaded. `None`
/// when no terminal claim records exactly this step: never a response
/// synthesized from a progression row or a queue row. Who may ask is the
/// calling read's own judgment; this only projects.
pub(crate) fn settled_step_for_caller(
    memory: &Memory<'_>,
    attempt: AttemptId,
    step_hash: [u8; 32],
) -> MemoryResult<Option<CallerSettledStep>> {
    let vault = memory.vault();
    let txn = vault.store.env.read_txn().map_err(Error::from)?;
    let Some(claim_id) = step_index_lookup_in_txn(vault, &txn, attempt, &step_hash)? else {
        return Ok(None);
    };
    let Some(body) = vault.get_claim_in_txn(&txn, &claim_id)? else {
        return Ok(None);
    };
    let Some((bound_attempt, bound_hash, model)) = terminal_step_identity(&body) else {
        return Ok(None);
    };
    if bound_attempt != attempt || bound_hash != step_hash {
        return Ok(None);
    }
    let decoded = decode_step_claim_value(&body.value)?;
    // The lane opens its own snapshots: this one closes first.
    drop(txn);
    let mut sources = vec![claim_id];
    sources.extend(response_artifact(&decoded));
    for source in &sources {
        if memory
            .get_entity_tolerant(&source.to_hex())?
            .value
            .is_none()
        {
            return Ok(Some(CallerSettledStep::Withheld { claim: claim_id }));
        }
    }
    let txn = vault.store.env.read_txn().map_err(Error::from)?;
    let response = load_step_response_in_txn(vault, &txn, &decoded).map_err(step_error)?;
    drop(txn);
    Ok(Some(CallerSettledStep::Readable(Box::new(
        SettledStepView {
            job_ref: bytes_to_hex_lower(attempt.as_bytes()),
            run_id: recorded_run_id(&body),
            claim_ref: claim_id.to_hex(),
            step_hash: bytes_to_hex_lower(&step_hash),
            model,
            purpose: decoded.purpose,
            params_hash: decoded.params_hash,
            response,
        },
    ))))
}

/// The stored response's `usage` of the terminal claim that records exactly
/// this step, read in the given txn with no lane gate (FIX 11450): the spend
/// a crash left unsettled. `None` when no terminal claim records this step.
/// A write txn passes as `&*wtxn`. Only the runner's own record counts: a
/// compaction step's call settled once on its run's meter (FIX 4816).
pub(crate) fn settled_step_usage_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    attempt: AttemptId,
    step_hash: &[u8; 32],
) -> MemoryResult<Option<LlmUsage>> {
    let Some(claim_id) = step_index_lookup_in_txn(vault, txn, attempt, step_hash)? else {
        return Ok(None);
    };
    let Some(body) = vault.get_claim_in_txn(txn, &claim_id)? else {
        return Ok(None);
    };
    let Some((bound_attempt, bound_hash, _)) = terminal_step_identity(&body) else {
        return Ok(None);
    };
    if bound_attempt != attempt || bound_hash != *step_hash {
        return Ok(None);
    }
    let decoded = decode_step_claim_value(&body.value)?;
    if !step_claim_is_runner_execution(&decoded, &body) {
        return Ok(None);
    }
    let response = load_step_response_in_txn(vault, txn, &decoded).map_err(step_error)?;
    Ok(Some(response.usage))
}

/// One page of `attempt`'s committed steps in the caller's snapshot: its
/// memo-index rows in step-hash order from `from_step` (64-hex, inclusive),
/// each kept only while its claim is still its producer's finished record
/// of exactly that step (FIX 4816), and the hash the next page starts at.
/// Refs only: no response is loaded.
pub(crate) fn committed_steps_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    attempt: AttemptId,
    from_step: Option<&str>,
    limit: usize,
) -> MemoryResult<(Vec<(String, EntityId)>, Option<String>)> {
    let from = match from_step {
        Some(hash) => decode_hash_hex(hash.trim())
            .map_err(|_| MemoryError::bad_request("from_step must be 64 hex characters"))?,
        None => [0; 32],
    };
    let index_key = |step_hash| StepIndexKey {
        attempt_id: attempt,
        step_hash,
    };
    let rows = STEP_INDEX_FORWARD
        .iter_range(
            &vault.store,
            txn,
            Bound::Included(&index_key(from)),
            Bound::Included(&index_key([u8::MAX; 32])),
        )?
        .take(limit.saturating_add(1))
        .collect::<Result<Vec<_>, Error>>()?;
    let next = rows
        .get(limit)
        .map(|(key, _)| bytes_to_hex_lower(&key.step_hash));
    let mut steps = Vec::new();
    for (key, claim_id) in rows.into_iter().take(limit) {
        let committed = vault
            .get_claim_in_txn(txn, &claim_id)?
            .as_ref()
            .and_then(terminal_step_identity)
            .is_some_and(|(bound_attempt, bound_hash, _)| {
                bound_attempt == attempt && bound_hash == key.step_hash
            });
        if committed {
            steps.push((bytes_to_hex_lower(&key.step_hash), claim_id));
        }
    }
    Ok((steps, next))
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

pub(super) fn step_error(error: DurableStepError) -> MemoryError {
    match error {
        DurableStepError::Engine(error) => error.into(),
        _ => Error::InvalidClaimBody("dreamer step response did not decode").into(),
    }
}
