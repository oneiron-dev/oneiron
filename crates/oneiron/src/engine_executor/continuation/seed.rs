//! Child-owned frozen continuation state, kept as reply-bearing content.

use serde::{Deserialize, Serialize};

use super::{
    ContinuationRefusal, FINAL_ROW_DOMAIN, PreparedExecutorContinuation, ProvedStart,
    continuation_digest, continuation_of, continuation_row_in_txn, continuation_tail_effect,
    prove_in_txn, source_in_txn,
};
use crate::code_run::{
    CodeRunDeterminism, CodeRunReplayRecord, ExecutorStorage, StoredRunContinuation,
    actor_gone_in_txn, continuation_prefix_digest, continuation_seed_body_in_txn,
    encode_code_run_replay_record, publish_continuation_output_in_txn, seed_continuation_run,
    step_replay_capsules_in_txn,
};
use crate::engine_executor::record::{
    executor_config_marker_bytes, validate_executor_config_marker_in_txn,
};
use crate::engine_executor::store::{CONFIG_OUTPUT_PATH, terminal_output_seq};
use crate::engine_executor::types::{
    EngineExecutorConfig, EngineExecutorError, EngineExecutorLimits,
};
use crate::{EntityId, Error, ModelId, ModelLocality, ModelTierRef, Vault};

/// The original capsule's cut, not a replacement for current source proof.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct SourceCut {
    pub(super) step: u64,
    pub(super) bridge_start: u64,
    pub(super) start_digest: [u8; 32],
}

#[derive(Serialize, Deserialize)]
struct FrozenSeed {
    continuation_digest: [u8; 32],
    actor: EntityId,
    task: String,
    model: ModelId,
    model_locality: ModelLocality,
    seat_effort: Option<crate::llm::ReasoningEffort>,
    global_tier: ModelTierRef,
    frozen_unix_ms: u64,
    rng_seed: [u8; crate::code_run::CODE_RUN_RNG_SEED_LEN],
    soft_steps: u32,
    prompt_fingerprint: String,
    cut: SourceCut,
    prefix_digest: [u8; 32],
}

fn seed_path(run: EntityId) -> String {
    format!("executor/repl/continuation/{}.seed.json", run.to_hex())
}

impl FrozenSeed {
    fn from_start(
        proved: ProvedStart,
        row: &StoredRunContinuation,
    ) -> Result<(Self, CodeRunReplayRecord), ContinuationRefusal> {
        let ProvedStart {
            body,
            prefix,
            actor,
            cut,
            ..
        } = proved;
        let clock = prefix
            .determinism
            .ok_or(ContinuationRefusal::SourceMissing)?;
        let prefix_digest = continuation_prefix_digest(&prefix, cut.step, cut.bridge_start)?
            .ok_or(ContinuationRefusal::NoCheckpoint)?;
        let state = Self {
            continuation_digest: continuation_digest(row),
            actor,
            task: body.task,
            model: body.model,
            model_locality: body.model_locality,
            seat_effort: body.seat_effort,
            global_tier: body.global_tier,
            frozen_unix_ms: clock.frozen_unix_ms,
            rng_seed: clock.rng_seed,
            soft_steps: body.soft_steps,
            prompt_fingerprint: body.prompt_fingerprint,
            cut,
            prefix_digest,
        };
        Ok((state, prefix))
    }

    fn config(&self, template: &EngineExecutorConfig) -> EngineExecutorConfig {
        EngineExecutorConfig {
            run_id: template.run_id,
            task: self.task.clone(),
            prompt_package_root: template.prompt_package_root.clone(),
            model: self.model.clone(),
            model_locality: self.model_locality,
            seat_effort: self.seat_effort,
            global_tier: self.global_tier.clone(),
            determinism: CodeRunDeterminism::new(self.frozen_unix_ms, self.rng_seed),
            limits: EngineExecutorLimits {
                soft_steps: self.soft_steps,
            },
        }
    }
}

pub(super) fn reopen(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    row: &StoredRunContinuation,
    child: &CodeRunReplayRecord,
    template: &EngineExecutorConfig,
) -> Result<PreparedExecutorContinuation, ContinuationRefusal> {
    let path = seed_path(child.run_id);
    let state = if let Some(output) = child.outputs.iter().find(|output| output.path == path) {
        let Some(bytes) = continuation_seed_body_in_txn(vault, txn, child.run_id, output)? else {
            return Err(ContinuationRefusal::NoCheckpoint);
        };
        let state: FrozenSeed =
            serde_json::from_slice(&bytes).map_err(|_| ContinuationRefusal::NoCheckpoint)?;
        if state.continuation_digest != continuation_digest(row) {
            return Err(ContinuationRefusal::Occupied);
        }
        if actor_gone_in_txn(vault, txn, &state.actor) {
            return Err(ContinuationRefusal::NoCheckpoint);
        }
        prove_seeded_source(vault, txn, row, child, &state)?;
        state
    } else {
        // A child without this witness still has its original full proof path.
        let proved = prove_in_txn(vault, txn, &continuation_of(row.clone()))?;
        if proved.digest != row.start_digest {
            return Err(ContinuationRefusal::NoCheckpoint);
        }
        FrozenSeed::from_start(proved, row)?.0
    };
    let config = state.config(template);
    validate_child(
        vault,
        txn,
        child,
        &config,
        &state.prompt_fingerprint,
        &state.continuation_digest,
    )?;
    Ok(PreparedExecutorContinuation {
        config,
        resume_step: row.step,
    })
}

/// The source still has the approved cut. The child supplies only the frozen
/// prefix and config; current predecessor, capsule and effect checks stay live.
fn prove_seeded_source(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    row: &StoredRunContinuation,
    child: &CodeRunReplayRecord,
    state: &FrozenSeed,
) -> Result<(), ContinuationRefusal> {
    let source = source_in_txn(vault, txn, &continuation_of(row.clone()))?;
    let capsules = step_replay_capsules_in_txn(vault, txn, row.source_run)?;
    let at_step = capsules
        .iter()
        .filter(|capsule| capsule.step == row.step && capsule.start.is_some())
        .max_by_key(|capsule| capsule.lease_generation);
    let capsule = at_step
        .or_else(|| {
            capsules
                .iter()
                .filter(|capsule| capsule.step < row.step && capsule.start.is_some())
                .max_by_key(|capsule| (capsule.lease_generation, capsule.step))
        })
        .ok_or(ContinuationRefusal::NoCheckpoint)?;
    let start = capsule
        .start
        .as_ref()
        .ok_or(ContinuationRefusal::NoCheckpoint)?;
    if capsule.lease_generation != row.lease_generation
        || capsule.step != state.cut.step
        || start.bridge_start != state.cut.bridge_start
        || start.digest != state.cut.start_digest
    {
        return Err(ContinuationRefusal::NoCheckpoint);
    }
    let bridge_start =
        usize::try_from(start.bridge_start).map_err(|_| ContinuationRefusal::NoCheckpoint)?;
    if source.determinism != child.determinism
        || continuation_prefix_digest(&source, state.cut.step, start.bridge_start)?
            != Some(state.prefix_digest)
    {
        return Err(ContinuationRefusal::NoCheckpoint);
    }
    if at_step.is_some() {
        if row.start_digest != start.digest {
            return Err(ContinuationRefusal::NoCheckpoint);
        }
        if source
            .bridge_calls
            .iter()
            .skip(bridge_start)
            .any(continuation_tail_effect)
        {
            return Err(ContinuationRefusal::EffectTail);
        }
    } else {
        let terminal = source
            .outputs
            .iter()
            .filter_map(|output| terminal_output_seq(&output.path))
            .any(|seq| seq >= capsule.step);
        if terminal || source.step_checkpoints.len() as u64 != row.step {
            return Err(ContinuationRefusal::NoCheckpoint);
        }
        let mut prefix = source;
        prefix.live_run = None;
        let mut hasher = blake3::Hasher::new();
        hasher.update(FINAL_ROW_DOMAIN);
        hasher.update(&start.digest);
        hasher.update(&encode_code_run_replay_record(&prefix)?);
        if *hasher.finalize().as_bytes() != row.start_digest {
            return Err(ContinuationRefusal::NoCheckpoint);
        }
    }
    Ok(())
}

fn validate_child(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    child: &CodeRunReplayRecord,
    config: &EngineExecutorConfig,
    fingerprint: &str,
    digest: &[u8; 32],
) -> Result<(), ContinuationRefusal> {
    if child.determinism != Some(config.determinism) {
        return Err(ContinuationRefusal::Occupied);
    }
    match validate_executor_config_marker_in_txn(
        vault,
        txn,
        child,
        config,
        fingerprint,
        Some(digest),
    ) {
        Ok(_) => Ok(()),
        Err(EngineExecutorError::Engine(Error::InvalidConfig(_))) => {
            Err(ContinuationRefusal::Occupied)
        }
        Err(error) => Err(error.into()),
    }
}

pub(super) fn create(
    vault: &Vault,
    leased: &crate::attempt_queue::AttemptRecord,
    template: &EngineExecutorConfig,
) -> Result<PreparedExecutorContinuation, ContinuationRefusal> {
    // Both bodies may spill. Mint their instances before opening the writer.
    let mint = vault.store.body_mint()?.reserve(2)?;
    let mut txn = vault.store.env.write_txn().map_err(Error::from)?;
    let row = continuation_row_in_txn(vault, &txn, leased, template)?;
    if let Some(child) = vault.get_code_run_replay_record_in_txn(&txn, &template.run_id)? {
        return reopen(vault, &txn, &row, &child, template);
    }
    // Re-prove inside this writer: neither actor erase nor source release can
    // race a snapshot-to-seed copy of the admitted task and inherited bodies.
    let proved = prove_in_txn(vault, &txn, &continuation_of(row.clone()))?;
    if proved.digest != row.start_digest || actor_gone_in_txn(vault, &txn, &proved.actor) {
        return Err(ContinuationRefusal::NoCheckpoint);
    }
    let (state, mut child) = FrozenSeed::from_start(proved, &row)?;
    let config = state.config(template);
    child.run_id = template.run_id;
    child.live_run = None;
    child
        .outputs
        .retain(|output| output.path != CONFIG_OUTPUT_PATH);
    let inherited = child.outputs.clone();
    // Only values already admitted in the source StepStartBody are copied.
    // Preserve their custody handles byte for byte, as capsule publication does.
    let bytes = serde_json::to_vec(&state)
        .map_err(|_| Error::InvariantViolation("continuation seed encoding"))?;
    let seed = publish_continuation_output_in_txn(
        vault,
        &mut txn,
        &mint,
        child.run_id,
        seed_path(child.run_id),
        &bytes,
    )?;
    let marker_bytes = executor_config_marker_bytes(
        &ExecutorStorage::Canonical(vault),
        &config,
        &state.prompt_fingerprint,
        Some(&state.continuation_digest),
    )?;
    let marker = publish_continuation_output_in_txn(
        vault,
        &mut txn,
        &mint,
        child.run_id,
        CONFIG_OUTPUT_PATH.to_owned(),
        &marker_bytes,
    )?;
    child.outputs.push(seed.output.clone());
    child.outputs.push(marker.output.clone());
    seed_continuation_run(
        vault,
        &mut txn,
        &child,
        row.source_run,
        state.actor,
        &inherited,
    )?;
    txn.commit().map_err(Error::from)?;
    // seed and marker keep their file pins until after this commit.
    Ok(PreparedExecutorContinuation {
        config,
        resume_step: row.step,
    })
}
