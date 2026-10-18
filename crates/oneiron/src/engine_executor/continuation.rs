//! Prompt continuations of failed agent runs (FIX 3694, OF-568).
//!
//! An owner approves a prompt note for a failed run. A successor attempt,
//! `retry_of` the failed one, carries the approved continuation in a row of
//! its own, written once beside its enqueue
//! ([`put_run_continuation_in_txn`]). Once the successor is leased, its
//! executor run (whose id is the successor's) is seeded from the failed
//! run's replay row as it stood at the start of the failing step
//! ([`fork_executor_run`]): the start that step's capture stored. A failing
//! step that may have committed an effect is kept instead (FIX 3694 PR 2):
//! the run is seeded from the row its failure left, so that step's program,
//! its calls, made once, and its error observation stay as history, and the
//! run goes on at the next step. The REPL never runs a prefix program again:
//! it rebuilds each turn from the stored programs and observations, and from
//! the cut on every turn carries the approved note as a message of its own
//! just before the turn instruction.
//!
//! The child runs the source's task, model, locality, seat effort, tier,
//! clock and limits. Its config marker binds the source's teaching
//! fingerprint and this continuation's digest, so a teaching that drifted
//! since, or another continuation, refuses through the marker check. A cut
//! that a call with an effect follows refuses
//! ([`ContinuationRefusal::EffectTail`]); [`pre_fail_checkpoint`] never
//! names one.

use super::record::{record_config_marker, validate_executor_config_marker};
use super::store::{CONFIG_OUTPUT_PATH, terminal_output_seq};
use super::types::{
    EngineExecutorConfig, EngineExecutorError, EngineExecutorLimits, EngineExecutorResult,
};
use crate::attempt_queue::{AttemptId, AttemptQueue, AttemptRecord, AttemptState};
use crate::code_run::{
    CodeRunBridgeCall, CodeRunReplayRecord, ExecutorStorage, SelfEffect, StepReplayCapsule,
    StepStartBody, StoredRunContinuation, capsule_start_body, decode_code_run_replay_record,
    encode_code_run_replay_record, put_run_continuation_row_in_txn, recorded_verb_call,
    run_continuation_in_txn, seed_continuation_run, step_replay_capsules_in_txn,
};
use crate::task_verb::sdk::AgentVerb;
use crate::{ContentPart, EntityId, Error, LlmMessage, LlmMessageRole, Vault};

/// The engine's framing of an approved note: the first part of the note's
/// message, before the approved bytes as a part of their own.
const CONTINUATION_NOTE_FRAME: &str =
    "An owner-approved note for this repaired run, which continues from where it failed:";

/// The domain of a continuation checkpoint's id.
const CHECKPOINT_REF_DOMAIN: &[u8] = b"oneiron:executor-continuation-checkpoint:v1";

/// The domain of a continuation's digest, which its child run's config
/// marker binds.
const CONTINUATION_DIGEST_DOMAIN: &[u8] = b"oneiron:executor-continuation:v1";

/// The domain of a cut after the failed step's digest: the start its config
/// comes from and the row the failure left.
const FINAL_ROW_DOMAIN: &[u8] = b"oneiron:executor-continuation-final-row:v1";

/// Where a continuation starts: before the model call of step `step` of
/// `source_run` (StartOfModelStep). The prefix it keeps is the run's
/// checkpoints `0..step`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExecutorCheckpointRef {
    pub source_run: EntityId,
    pub step: u64,
}

impl ExecutorCheckpointRef {
    /// The checkpoint's own id, never the run's or the attempt's: BLAKE3
    /// over a domain tag, the run and the step, cut to an id.
    ///
    /// # Errors
    ///
    /// A digest that falls in the reserved id range.
    pub fn id(&self) -> crate::Result<EntityId> {
        let mut hasher = blake3::Hasher::new();
        hasher.update(CHECKPOINT_REF_DOMAIN);
        hasher.update(self.source_run.as_bytes());
        hasher.update(&self.step.to_le_bytes());
        let mut bytes = [0_u8; 16];
        bytes.copy_from_slice(&hasher.finalize().as_bytes()[..16]);
        EntityId::from_bytes(bytes)
    }
}

/// One approved prompt continuation of a failed agent run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunContinuation {
    /// The Failed attempt.
    pub predecessor: AttemptId,
    pub checkpoint: ExecutorCheckpointRef,
    /// The owner's durable approval.
    pub approval: EntityId,
    /// The exact approved bytes.
    pub prompt: String,
}

/// The run a leased successor goes on as: its config, and the step it
/// resumes at.
#[derive(Debug, Clone, PartialEq)]
pub struct PreparedExecutorContinuation {
    pub config: EngineExecutorConfig,
    pub resume_step: u64,
}

/// Why a continuation cannot be written or forked. The card's apply door
/// shows the code; a refusal at lease time fails the successor with it.
#[derive(Debug, thiserror::Error)]
pub enum ContinuationRefusal {
    /// The source run holds no start for the step, or that start no longer
    /// proves the run's row.
    #[error("continuation_no_checkpoint")]
    NoCheckpoint,
    /// The failing step committed effects after the cut.
    #[error("continuation_effect_tail")]
    EffectTail,
    /// The predecessor is not a Failed attempt, the checkpoint names another
    /// run or the run has no replay row; or the successor carries no
    /// continuation.
    #[error("continuation_source_missing")]
    SourceMissing,
    /// The successor already holds another continuation, or its run is
    /// another one's.
    #[error("continuation_occupied")]
    Occupied,
    /// A storage error, or a lease that does not bind the successor's run.
    #[error("continuation_storage: {0}")]
    Storage(#[from] Error),
}

impl ContinuationRefusal {
    /// The refusal's stable code.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::NoCheckpoint => "continuation_no_checkpoint",
            Self::EffectTail => "continuation_effect_tail",
            Self::SourceMissing => "continuation_source_missing",
            Self::Occupied => "continuation_occupied",
            Self::Storage(_) => "continuation_storage",
        }
    }
}

impl From<EngineExecutorError> for ContinuationRefusal {
    fn from(error: EngineExecutorError) -> Self {
        match error {
            EngineExecutorError::Engine(error) => Self::Storage(error),
            other => Self::Storage(Error::InvalidConfig(format!(
                "continuation seed: {}",
                other.variant()
            ))),
        }
    }
}

/// The approved note a child run carries on its turns.
pub(super) struct ContinuationNote {
    /// The step the child continues at; every turn from it on carries the
    /// note.
    pub(super) step: u64,
    /// The approved bytes.
    pub(super) prompt: String,
    /// The continuation's digest, which the child's config marker binds.
    pub(super) digest: [u8; 32],
}

/// A start a continuation forks from, proved in one snapshot.
struct ProvedStart {
    /// The start body, decoded.
    body: StepStartBody,
    /// The prefix row it holds.
    prefix: CodeRunReplayRecord,
    /// BLAKE3 of the start body.
    digest: [u8; 32],
    /// The lease generation of the capsule that holds it.
    lease_generation: u32,
}

/// Validates `continuation`, then writes it as `successor`'s, in `txn`, the
/// write transaction that enqueues `successor`. A continuation `successor`
/// already holds answers `Ok` again; another refuses.
///
/// # Errors
///
/// [`ContinuationRefusal`]: the source is missing, no start proves the
/// step, the failing step has an effect tail, the successor holds another
/// continuation, or storage failed.
pub fn put_run_continuation_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    successor: AttemptId,
    continuation: &RunContinuation,
) -> Result<(), ContinuationRefusal> {
    let proved = prove_in_txn(vault, txn, continuation)?;
    let mut row = StoredRunContinuation {
        predecessor: continuation.predecessor,
        source_run: continuation.checkpoint.source_run,
        step: continuation.checkpoint.step,
        approval: continuation.approval,
        prompt: continuation.prompt.clone(),
        // Taken over the stored bytes as the row is written.
        prompt_digest: [0; 32],
        start_digest: proved.digest,
        lease_generation: proved.lease_generation,
    };
    match put_run_continuation_row_in_txn(vault, txn, attempt_key(successor)?, &mut row)? {
        Some(held) if !same_continuation(&held, &row) => Err(ContinuationRefusal::Occupied),
        _ => Ok(()),
    }
}

/// The continuation `attempt` carries, if any.
///
/// # Errors
///
/// Storage errors.
pub fn run_continuation(
    vault: &Vault,
    attempt: AttemptId,
) -> crate::Result<Option<RunContinuation>> {
    let txn = vault.store.env.read_txn()?;
    Ok(run_continuation_in_txn(vault, &txn, attempt_key(attempt)?)?.map(continuation_of))
}

/// Seeds the executor run of `leased_successor`, a leased attempt that
/// carries a continuation, from the source run's start at the continued
/// step, and answers the config it runs under. The config is
/// `child_template` with the source's task, model, locality, seat effort,
/// tier and limits, from the start, and its clock, from the prefix row. A
/// fork made before is re-opened, never seeded twice.
///
/// # Errors
///
/// The refusals [`put_run_continuation_in_txn`] makes, checked again;
/// [`ContinuationRefusal::SourceMissing`] when the successor carries no
/// continuation; [`ContinuationRefusal::Occupied`] when its run is another
/// one's; and a storage error for a successor that is not leased as the
/// continued run.
pub fn fork_executor_run(
    vault: &Vault,
    leased_successor: &AttemptRecord,
    child_template: &EngineExecutorConfig,
) -> Result<PreparedExecutorContinuation, ContinuationRefusal> {
    let successor = attempt_key(leased_successor.id)?;
    let (row, proved) = {
        let txn = vault.store.env.read_txn().map_err(Error::from)?;
        let Some(row) = run_continuation_in_txn(vault, &txn, successor)? else {
            return Err(ContinuationRefusal::SourceMissing);
        };
        if !matches!(leased_successor.state, AttemptState::Leased)
            || leased_successor.retry_of != Some(row.predecessor)
            || child_template.run_id != successor
        {
            return Err(Error::InvalidConfig(
                "continuation fork: the successor is not leased as the continued run".to_owned(),
            )
            .into());
        }
        let proved = prove_in_txn(vault, &txn, &continuation_of(row.clone()))?;
        if proved.digest != row.start_digest {
            return Err(ContinuationRefusal::NoCheckpoint);
        }
        (row, proved)
    };
    let ProvedStart { body, prefix, .. } = proved;
    let config = EngineExecutorConfig {
        run_id: successor,
        task: body.task,
        prompt_package_root: child_template.prompt_package_root.clone(),
        model: body.model,
        model_locality: body.model_locality,
        seat_effort: body.seat_effort,
        global_tier: body.global_tier,
        determinism: prefix.determinism,
        limits: EngineExecutorLimits {
            soft_steps: body.soft_steps,
            hard_steps: body.hard_steps,
        },
    };
    let seed = ChildSeed {
        config: &config,
        prompt_fingerprint: &body.prompt_fingerprint,
        digest: continuation_digest(&row),
        source: row.source_run,
    };
    seed.seed_or_reopen(vault, prefix)?;
    Ok(PreparedExecutorContinuation {
        config,
        resume_step: row.step,
    })
}

/// The run a fork seeds: its config, the teaching it runs under, its
/// continuation's digest and the run it forks from.
struct ChildSeed<'a> {
    config: &'a EngineExecutorConfig,
    prompt_fingerprint: &'a str,
    digest: [u8; 32],
    source: EntityId,
}

impl ChildSeed<'_> {
    /// Seeds the child's replay row from `prefix`, or re-opens the fork a
    /// seed before this one made. The child holds the prefix's checkpoints,
    /// bridge calls, bindings and outputs, each output as an occurrence of
    /// its own, and a config marker of its own for the source's. A seed that
    /// loses to a concurrent one re-opens that one.
    fn seed_or_reopen(
        &self,
        vault: &Vault,
        prefix: CodeRunReplayRecord,
    ) -> Result<(), ContinuationRefusal> {
        let storage = ExecutorStorage::Canonical(vault);
        if let Some(child) = vault.get_code_run_replay_record(&self.config.run_id)? {
            return self.reopen(&storage, &child);
        }
        let mut child = prefix;
        child.run_id = self.config.run_id;
        child.live_run = None;
        child
            .outputs
            .retain(|output| output.path != CONFIG_OUTPUT_PATH);
        let inherited = child.outputs.clone();
        record_config_marker(
            &storage,
            &mut child,
            self.config,
            self.prompt_fingerprint,
            Some(&self.digest),
        )?;
        match seed_continuation_run(vault, &child, self.source, &inherited) {
            Ok(_) => Ok(()),
            Err(Error::ConcurrentWrite(_)) => {
                let seeded = vault
                    .get_code_run_replay_record(&self.config.run_id)?
                    .ok_or(Error::ConcurrentWrite("code-run continuation seed"))?;
                self.reopen(&storage, &seeded)
            }
            Err(error) => Err(error.into()),
        }
    }

    /// Re-opens a fork already seeded: the child's row must hold this
    /// continuation's clock and config marker, else it is another run's.
    fn reopen(
        &self,
        storage: &ExecutorStorage<'_>,
        child: &CodeRunReplayRecord,
    ) -> Result<(), ContinuationRefusal> {
        if child.determinism != self.config.determinism {
            return Err(ContinuationRefusal::Occupied);
        }
        match validate_executor_config_marker(
            storage,
            child,
            self.config,
            self.prompt_fingerprint,
            Some(&self.digest),
        ) {
            Ok(_) => Ok(()),
            Err(EngineExecutorError::Engine(Error::InvalidConfig(_))) => {
                Err(ContinuationRefusal::Occupied)
            }
            Err(error) => Err(error.into()),
        }
    }
}

/// The approved note `run` carries, when it is a canonical run forked from a
/// failed one; an off-record run carries none.
pub(super) fn continuation_note(
    storage: &ExecutorStorage<'_>,
    run: EntityId,
) -> EngineExecutorResult<Option<ContinuationNote>> {
    let ExecutorStorage::Canonical(vault) = storage else {
        return Ok(None);
    };
    let txn = vault.store.env.read_txn().map_err(Error::from)?;
    let note = run_continuation_in_txn(vault, &txn, run)?.map(|row| ContinuationNote {
        step: row.step,
        digest: continuation_digest(&row),
        prompt: row.prompt,
    });
    Ok(note)
}

/// The approved note's message on a turn of the child run: every turn from
/// the continued step on carries it, just before the turn instruction and
/// outside every compactable span; a turn before that step carries none.
pub(super) fn turn_note(
    note: Option<&ContinuationNote>,
    completed_steps: u64,
) -> Option<LlmMessage> {
    let note = note.filter(|note| completed_steps >= note.step)?;
    Some(LlmMessage {
        role: LlmMessageRole::User,
        content: vec![
            ContentPart::Text {
                text: CONTINUATION_NOTE_FRAME.to_owned(),
            },
            ContentPart::Text {
                text: note.prompt.clone(),
            },
        ],
    })
}

/// The checkpoint a failed run continues from: the step of its latest
/// captured start (by lease generation, then step), else its completed-step
/// count, 0 with no replay row. When a call the row holds after that start
/// may have committed an effect, and the failed step was checkpointed, it is
/// the row's checkpoint count instead (FIX 3694 PR 2): the cut after the
/// failed step, whose calls are then never made again.
///
/// # Errors
///
/// Storage errors.
pub fn pre_fail_checkpoint(vault: &Vault, run: EntityId) -> crate::Result<ExecutorCheckpointRef> {
    let txn = vault.store.env.read_txn()?;
    let capsules = step_replay_capsules_in_txn(vault, &txn, run)?;
    pre_fail_checkpoint_of(vault, &txn, run, &capsules)
}

/// The checkpoint of `failed`'s run that `id` names, when one does: a step
/// whose start the run captured, or the run's [`pre_fail_checkpoint`].
///
/// # Errors
///
/// Storage errors.
pub fn checkpoint_ref(
    vault: &Vault,
    failed: AttemptId,
    id: EntityId,
) -> crate::Result<Option<ExecutorCheckpointRef>> {
    let run = attempt_key(failed)?;
    let txn = vault.store.env.read_txn()?;
    let capsules = step_replay_capsules_in_txn(vault, &txn, run)?;
    for capsule in capsules.iter().filter(|capsule| capsule.start.is_some()) {
        let checkpoint = ExecutorCheckpointRef {
            source_run: run,
            step: capsule.step,
        };
        if checkpoint.id()? == id {
            return Ok(Some(checkpoint));
        }
    }
    let checkpoint = pre_fail_checkpoint_of(vault, &txn, run, &capsules)?;
    Ok((checkpoint.id()? == id).then_some(checkpoint))
}

/// [`pre_fail_checkpoint`] over `capsules`, the run's, in `rtxn`.
fn pre_fail_checkpoint_of(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    run: EntityId,
    capsules: &[StepReplayCapsule],
) -> crate::Result<ExecutorCheckpointRef> {
    let latest = capsules
        .iter()
        .filter(|capsule| capsule.start.is_some())
        .max_by_key(|capsule| (capsule.lease_generation, capsule.step));
    let source = vault.get_code_run_replay_record_in_txn(rtxn, &run)?;
    let completed = source
        .as_ref()
        .map_or(0, |record| record.step_checkpoints.len() as u64);
    let step = match latest {
        Some(capsule)
            if completed > capsule.step
                && source
                    .as_ref()
                    .is_some_and(|record| effect_after(record, capsule)) =>
        {
            completed
        }
        Some(capsule) => capsule.step,
        None => completed,
    };
    Ok(ExecutorCheckpointRef {
        source_run: run,
        step,
    })
}

/// Proves `continuation` as `rtxn` sees the vault: the predecessor is a
/// Failed attempt whose run is the checkpoint's and has a replay row; that
/// run's capsule for the step (its latest lease generation that holds a
/// start) holds a start whose body is still there, clean and its digest,
/// and whose prefix row the run's row still descends from; and no call
/// after the cut may have committed an effect. A step with no start that is
/// the row's checkpoint count is a cut after the failed step, proved from
/// the row the failure left ([`prove_final_row`]).
fn prove_in_txn(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    continuation: &RunContinuation,
) -> Result<ProvedStart, ContinuationRefusal> {
    let source_run = continuation.checkpoint.source_run;
    let step = continuation.checkpoint.step;
    let failed = AttemptQueue::new(vault)
        .get_in_txn(rtxn, continuation.predecessor)?
        .is_some_and(|attempt| matches!(attempt.state, AttemptState::Failed));
    if !failed || source_run.as_bytes() != continuation.predecessor.as_bytes() {
        return Err(ContinuationRefusal::SourceMissing);
    }
    let Some(source) = vault.get_code_run_replay_record_in_txn(rtxn, &source_run)? else {
        return Err(ContinuationRefusal::SourceMissing);
    };
    let capsules = step_replay_capsules_in_txn(vault, rtxn, source_run)?;
    let capsule = capsules
        .iter()
        .filter(|capsule| capsule.step == step && capsule.start.is_some())
        .max_by_key(|capsule| capsule.lease_generation);
    let Some(capsule) = capsule else {
        return prove_final_row(vault, rtxn, &source, step, &capsules);
    };
    let Some((proved, bridge_start)) = decode_start(vault, rtxn, capsule)? else {
        return Err(ContinuationRefusal::NoCheckpoint);
    };
    if !descends(&source, &proved.prefix, step, bridge_start) {
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
    Ok(proved)
}

/// Proves a cut after the failed run's last step, from the row its failure
/// left (FIX 3694 PR 2): `step` is that row's checkpoint count, the config
/// is the latest start the run captured before it, the row still descends
/// from that start, and no step from that start on ended on a terminal
/// marker. No call follows the cut, so none can have an effect after it.
fn prove_final_row(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    source: &CodeRunReplayRecord,
    step: u64,
    capsules: &[StepReplayCapsule],
) -> Result<ProvedStart, ContinuationRefusal> {
    let latest = capsules
        .iter()
        .filter(|capsule| capsule.step < step && capsule.start.is_some())
        .max_by_key(|capsule| (capsule.lease_generation, capsule.step));
    let Some(capsule) = latest.filter(|_| source.step_checkpoints.len() as u64 == step) else {
        return Err(ContinuationRefusal::NoCheckpoint);
    };
    let Some((start, bridge_start)) = decode_start(vault, rtxn, capsule)? else {
        return Err(ContinuationRefusal::NoCheckpoint);
    };
    let terminal = source
        .outputs
        .iter()
        .filter_map(|output| terminal_output_seq(&output.path))
        .any(|seq| seq >= capsule.step);
    if terminal || !descends(source, &start.prefix, capsule.step, bridge_start) {
        return Err(ContinuationRefusal::NoCheckpoint);
    }
    let mut prefix = source.clone();
    prefix.live_run = None;
    let mut hasher = blake3::Hasher::new();
    hasher.update(FINAL_ROW_DOMAIN);
    hasher.update(&start.digest);
    hasher.update(&encode_code_run_replay_record(&prefix)?);
    Ok(ProvedStart {
        body: start.body,
        prefix,
        digest: *hasher.finalize().as_bytes(),
        lease_generation: start.lease_generation,
    })
}

/// Whether a call `record` holds after the start `capsule` captured may have
/// committed an effect.
fn effect_after(record: &CodeRunReplayRecord, capsule: &StepReplayCapsule) -> bool {
    capsule
        .start
        .as_ref()
        .and_then(|start| usize::try_from(start.bridge_start).ok())
        .is_some_and(|start| {
            record
                .bridge_calls
                .iter()
                .skip(start)
                .any(continuation_tail_effect)
        })
}

/// The start `capsule` holds, decoded, with the bridge log's length at it;
/// `None` when its body is gone, withheld or not its digest, or does not
/// decode as a start.
fn decode_start(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    capsule: &StepReplayCapsule,
) -> crate::Result<Option<(ProvedStart, usize)>> {
    let Some(start) = &capsule.start else {
        return Ok(None);
    };
    let Some(bytes) = capsule_start_body(vault, rtxn, capsule)? else {
        return Ok(None);
    };
    let Ok(body) = rmp_serde::from_slice::<StepStartBody>(&bytes) else {
        return Ok(None);
    };
    let (Ok(prefix), Ok(bridge_start)) = (
        decode_code_run_replay_record(&body.record),
        usize::try_from(start.bridge_start),
    ) else {
        return Ok(None);
    };
    Ok(Some((
        ProvedStart {
            body,
            prefix,
            digest: start.digest,
            lease_generation: capsule.lease_generation,
        },
        bridge_start,
    )))
}

/// Whether `source`, the run's row now, still descends from `prefix`, the
/// row a start holds: the same run and clock, exactly `step` checkpoints and
/// `bridge_start` bridge calls, each as the source still holds it.
fn descends(
    source: &CodeRunReplayRecord,
    prefix: &CodeRunReplayRecord,
    step: u64,
    bridge_start: usize,
) -> bool {
    prefix.run_id == source.run_id
        && prefix.determinism == source.determinism
        && prefix.step_checkpoints.len() as u64 == step
        && prefix.bridge_calls.len() == bridge_start
        && source.step_checkpoints.get(..prefix.step_checkpoints.len())
            == Some(prefix.step_checkpoints.as_slice())
        && source.bridge_calls.get(..bridge_start) == Some(prefix.bridge_calls.as_slice())
}

/// Whether a source call after the cut may have committed an effect that a
/// continuation would repeat or lose. Reads and the run's own bookkeeping
/// have none: a context descriptor, a hidden thought, a memory search, an
/// inference-defaults read, the leader's advice, a wait, a fold of the
/// run's own log, and a verb call whose verb does not write. Any other call
/// may, a verb this engine does not know as a read included.
fn continuation_tail_effect(call: &CodeRunBridgeCall) -> bool {
    match call.effect {
        SelfEffect::Context
        | SelfEffect::Think
        | SelfEffect::MemorySearch
        | SelfEffect::InferenceDefaultsRead
        | SelfEffect::Leader
        | SelfEffect::TasksWait
        | SelfEffect::TasksWaitSet
        | SelfEffect::Fold => false,
        SelfEffect::AgentVerb => recorded_verb_call(call)
            .and_then(|(verb, _)| AgentVerb::from_name(verb))
            .is_none_or(AgentVerb::writes),
        _ => true,
    }
}

/// The continuation's digest, which its child run's config marker binds:
/// BLAKE3 over a domain tag, the predecessor, the source run, the step, the
/// approval, the prompt's BLAKE3 and the start body's digest.
fn continuation_digest(row: &StoredRunContinuation) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(CONTINUATION_DIGEST_DOMAIN);
    hasher.update(row.predecessor.as_bytes());
    hasher.update(row.source_run.as_bytes());
    hasher.update(&row.step.to_le_bytes());
    hasher.update(row.approval.as_bytes());
    hasher.update(blake3::hash(row.prompt.as_bytes()).as_bytes());
    hasher.update(&row.start_digest);
    *hasher.finalize().as_bytes()
}

/// Whether two rows are one continuation: the same predecessor, run, step,
/// approval and prompt bytes.
fn same_continuation(held: &StoredRunContinuation, row: &StoredRunContinuation) -> bool {
    held.predecessor == row.predecessor
        && held.source_run == row.source_run
        && held.step == row.step
        && held.approval == row.approval
        && held.prompt == row.prompt
}

/// The continuation a stored row holds.
fn continuation_of(row: StoredRunContinuation) -> RunContinuation {
    RunContinuation {
        predecessor: row.predecessor,
        checkpoint: ExecutorCheckpointRef {
            source_run: row.source_run,
            step: row.step,
        },
        approval: row.approval,
        prompt: row.prompt,
    }
}

/// The continuation table's key for `attempt`: its 16 bytes, as its run's
/// id is.
fn attempt_key(attempt: AttemptId) -> crate::Result<EntityId> {
    EntityId::from_bytes(*attempt.as_bytes())
}
