//! The source an arm runs from (PR-S1): one captured step of a canonical
//! run, read from its capsule and frozen before the arm starts. Its request
//! as stored and its start are read through the capsule's own readers, which
//! check withholding and digests; the start's prefix row must be the run's
//! row at the step (its run, exactly as many checkpoints as the step's
//! number, its bridge log at the step's start), and the step's own calls
//! come from a record that proves where they end: the next step's captured
//! start, or the run's row once the step is its last checkpoint. A step
//! whose end nothing proves, or a body that is gone, is unavailable, never
//! assumed. The run's results and observations before the step are frozen
//! with the taint they read under, so the arm reads no live state.

use super::types::{
    ShadowBodyRef, ShadowDeterminism, ShadowRequestDigest, ShadowStepIdentity, ShadowUnavailable,
    ShadowUnavailableReason as Reason,
};
use crate::code_run::{
    CapsuleRequest, CapsuleRungBinding, CodeRunDeterminism, CodeRunRawOutput, CodeRunReplayRecord,
    ExecutorStepStart, ReplayRoutePin, StepReplayCapsule, StepStartBody, capsule_request,
    capsule_start_body, decode_code_run_replay_record, step_replay_capsules_in_txn,
};
use crate::limit_ask::EngineLimit;
use crate::secret_rotation::ArtifactTaintState;
use crate::{LlmRequest, Result, Vault};

/// An arm's source, or why it has none.
type Outcome<T> = std::result::Result<T, ShadowUnavailable>;

/// One result or observation of the step's run before the step, frozen for
/// the arm: its manifest, the taint the run's occurrence of it read under,
/// and its bytes while it is clean. A body that is not clean is never read.
pub(crate) struct FrozenBody {
    pub(crate) output: CodeRunRawOutput,
    pub(crate) state: ArtifactTaintState,
    pub(crate) secret: Option<String>,
    pub(crate) bytes: Option<Vec<u8>>,
}

/// One captured step, read and frozen for an arm: its request as stored,
/// its run's row before the step, the record that holds the step's own
/// calls to their end, and the bodies the step's program may read back.
pub struct PreparedShadowStep {
    pub(crate) step: ShadowStepIdentity,
    pub(crate) request: LlmRequest,
    pub(crate) request_digest: ShadowRequestDigest,
    pub(crate) binding: Option<CapsuleRungBinding>,
    pub(crate) route_pin: Option<ReplayRoutePin>,
    pub(crate) seed: Option<u64>,
    pub(crate) start: ExecutorStepStart,
    pub(crate) determinism: CodeRunDeterminism,
    /// The run's row as the step started.
    pub(crate) prefix: CodeRunReplayRecord,
    /// A row that holds the step's calls, `bridge_start..bridge_end`.
    pub(crate) window: CodeRunReplayRecord,
    pub(crate) bridge_start: u64,
    pub(crate) bridge_end: u64,
    pub(crate) frozen: Vec<FrozenBody>,
    /// The vault's `[limits]` scan row, frozen for the arm's reads.
    pub(crate) scan_bytes: u64,
}

impl PreparedShadowStep {
    /// The step it is.
    #[must_use]
    pub const fn step(&self) -> &ShadowStepIdentity {
        &self.step
    }

    /// The step's request as stored, each secret in it its custody handle.
    #[must_use]
    pub const fn request(&self) -> &LlmRequest {
        &self.request
    }

    /// Which copy of its request the step keeps, by its digest.
    #[must_use]
    pub const fn request_digest(&self) -> ShadowRequestDigest {
        self.request_digest
    }

    /// The rung that answered the captured call, when one did.
    #[must_use]
    pub const fn binding(&self) -> Option<&CapsuleRungBinding> {
        self.binding.as_ref()
    }

    /// The route that rung went out on, when it pinned one.
    #[must_use]
    pub const fn route_pin(&self) -> Option<&ReplayRoutePin> {
        self.route_pin.as_ref()
    }

    /// The sampling seed the captured request carried, if any.
    #[must_use]
    pub const fn seed(&self) -> Option<u64> {
        self.seed
    }

    /// The start the step runs from.
    #[must_use]
    pub const fn start(&self) -> &ExecutorStepStart {
        &self.start
    }

    /// The run's guest clock and seed.
    #[must_use]
    pub fn determinism(&self) -> ShadowDeterminism {
        self.determinism.into()
    }

    /// Where the step's calls are in its run's bridge log.
    #[must_use]
    pub const fn bridge_window(&self) -> (u64, u64) {
        (self.bridge_start, self.bridge_end)
    }

    /// Whether each of `refs` names a body granted to the arm: one of the
    /// run's results or observations before the step, frozen clean.
    ///
    /// # Errors
    ///
    /// The first ref the arm was not granted: one frozen withheld, or one
    /// that is no body of the step's run before it.
    pub fn check_refs(&self, refs: &[ShadowBodyRef]) -> Outcome<()> {
        for wanted in refs {
            let found = self.frozen.iter().find(|frozen| {
                frozen.output.path == wanted.path && frozen.output.output_ref() == wanted.body
            });
            match found {
                Some(frozen) if frozen.bytes.is_some() => {}
                Some(_) => return Err(unavailable(Reason::SourceWithheld, "body_ref")),
                None => return Err(unavailable(Reason::SourceMissing, "body_ref")),
            }
        }
        Ok(())
    }
}

/// `reason`, caused by `cause`.
fn unavailable(reason: Reason, cause: &str) -> ShadowUnavailable {
    ShadowUnavailable::new(reason, cause)
}

/// The step `capsule` captured, read and frozen for an arm, or why it
/// cannot be: an erased capsule, a withheld or unreadable request or start
/// (`SourceWithheld`), no start (`SourceMissing`), a start that is not the
/// run's row at the step (`SourceDigestMismatch`), a step whose end nothing
/// proves (`CapturedOutcomeMissing`), or a body of its run that is gone
/// (`SourceMissing`). Everything is read here, before the arm starts.
///
/// # Errors
///
/// Storage errors.
pub fn prepare_shadow_step_source(
    vault: &Vault,
    capsule: &StepReplayCapsule,
) -> Result<Outcome<PreparedShadowStep>> {
    if capsule.content.actor().is_none() {
        return Ok(Err(unavailable(Reason::SourceWithheld, "capsule_erased")));
    }
    let Some(request_digest) = ShadowRequestDigest::of_capsule(capsule) else {
        return Ok(Err(unavailable(Reason::SourceWithheld, "request_withheld")));
    };
    let Some(start) = capsule.start.clone() else {
        return Ok(Err(unavailable(Reason::SourceMissing, "no_start")));
    };
    let Some(request) = capsule_request(vault, capsule)? else {
        return Ok(Err(unavailable(
            Reason::SourceWithheld,
            "request_unreadable",
        )));
    };
    let read = {
        let rtxn = vault.store.env.read_txn()?;
        read_step_in_txn(vault, &rtxn, capsule, &start)?
    };
    let (prefix, window) = match read {
        Ok(read) => read,
        Err(unavailable) => return Ok(Err(unavailable)),
    };
    let frozen = match freeze_bodies(vault, capsule.run, &prefix)? {
        Ok(frozen) => frozen,
        Err(unavailable) => return Ok(Err(unavailable)),
    };
    let bridge_end = window.bridge_calls.len() as u64;
    Ok(Ok(PreparedShadowStep {
        step: ShadowStepIdentity::of(capsule),
        request,
        request_digest,
        binding: capsule.binding.clone(),
        route_pin: capsule.route_pin.clone(),
        seed: capsule.seed,
        determinism: prefix.determinism,
        bridge_start: start.bridge_start,
        bridge_end,
        start,
        prefix,
        window,
        frozen,
        scan_bytes: vault.limit_watch().bound(EngineLimit::CodeResultScanBytes),
    }))
}

/// The step's start prefix and the record that holds its calls to their
/// end, read in `rtxn`.
fn read_step_in_txn(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    capsule: &StepReplayCapsule,
    start: &ExecutorStepStart,
) -> Result<Outcome<(CodeRunReplayRecord, CodeRunReplayRecord)>> {
    let Some(bytes) = capsule_start_body(vault, rtxn, capsule)? else {
        return Ok(Err(unavailable(Reason::SourceWithheld, "start_unreadable")));
    };
    let Some(prefix) = start_prefix(&bytes) else {
        return Ok(Err(unavailable(
            Reason::SourceDigestMismatch,
            "start_undecodable",
        )));
    };
    if prefix.run_id != capsule.run
        || prefix.step_checkpoints.len() as u64 != capsule.step
        || prefix.bridge_calls.len() as u64 != start.bridge_start
    {
        return Ok(Err(unavailable(
            Reason::SourceDigestMismatch,
            "start_prefix",
        )));
    }
    Ok(match step_end_in_txn(vault, rtxn, capsule, &prefix)? {
        Some(window) => Ok((prefix, window)),
        None => Err(unavailable(Reason::CapturedOutcomeMissing, "step_end")),
    })
}

/// The run's row a start body holds, when it decodes as a start.
fn start_prefix(bytes: &[u8]) -> Option<CodeRunReplayRecord> {
    let body = rmp_serde::from_slice::<StepStartBody>(bytes).ok()?;
    decode_code_run_replay_record(&body.record).ok()
}

/// The record that holds the step's calls to their proved end, read in
/// `rtxn`: the next step's captured start under the same lease, else the
/// run's row as stored once the step is its last checkpoint. Either must
/// descend from `prefix`. `None` when neither proves where the step ends: a
/// later row's checkpoints do not say where one step's calls stop.
fn step_end_in_txn(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    capsule: &StepReplayCapsule,
    prefix: &CodeRunReplayRecord,
) -> Result<Option<CodeRunReplayRecord>> {
    let next_step = capsule.step.saturating_add(1);
    let next = step_replay_capsules_in_txn(vault, rtxn, capsule.attempt)?
        .into_iter()
        .find(|next| {
            next.lease_generation == capsule.lease_generation
                && next.run == capsule.run
                && next.step == next_step
                && next.start.is_some()
        });
    if let Some(next) = next
        && let Some(bytes) = capsule_start_body(vault, rtxn, &next)?
        && let Some(record) = start_prefix(&bytes)
        && next
            .start
            .as_ref()
            .is_some_and(|start| start.bridge_start == record.bridge_calls.len() as u64)
        && ends_step(&record, prefix, capsule.step)
    {
        return Ok(Some(record));
    }
    let Some(mut record) = vault.get_code_run_replay_record_in_txn(rtxn, &capsule.run)? else {
        return Ok(None);
    };
    record.live_run = None;
    Ok(ends_step(&record, prefix, capsule.step).then_some(record))
}

/// Whether `record` descends from `prefix`, the run's row as step `step`
/// started (its run and clock, its checkpoints and bridge calls as the
/// prefix holds them), and its last checkpoint is the step's own.
fn ends_step(record: &CodeRunReplayRecord, prefix: &CodeRunReplayRecord, step: u64) -> bool {
    let bridge_start = prefix.bridge_calls.len();
    record.run_id == prefix.run_id
        && record.determinism == prefix.determinism
        && record.step_checkpoints.len() as u64 == step.saturating_add(1)
        && record.step_checkpoints.get(..prefix.step_checkpoints.len())
            == Some(prefix.step_checkpoints.as_slice())
        && record.bridge_calls.get(..bridge_start) == Some(prefix.bridge_calls.as_slice())
}

/// The bodies of `run` before the step its row `prefix` holds that the
/// step's program may read back, each with the taint the run's occurrence of
/// it reads under now, and its bytes while it is clean. A clean body that is
/// gone is unavailable. The bytes frozen are measured, never capped.
fn freeze_bodies(
    vault: &Vault,
    run: crate::EntityId,
    prefix: &CodeRunReplayRecord,
) -> Result<Outcome<Vec<FrozenBody>>> {
    let mut frozen = Vec::new();
    let mut frozen_bytes = 0_u64;
    for output in crate::engine_executor::shadow_readable_outputs(prefix) {
        let state = vault.code_run_raw_output_taint_state(Some(run), &output)?;
        let secret = vault.code_run_raw_output_secret(Some(run), &output)?;
        let bytes = if state.is_tainted() {
            None
        } else {
            let Some(bytes) = vault.get_code_run_raw_output(&output)? else {
                return Ok(Err(unavailable(Reason::SourceMissing, "prefix_body")));
            };
            frozen_bytes = frozen_bytes.saturating_add(bytes.len() as u64);
            Some(bytes)
        };
        frozen.push(FrozenBody {
            output,
            state,
            secret,
            bytes,
        });
    }
    tracing::debug!(
        bodies = frozen.len(),
        frozen_bytes,
        "a shadow step's earlier bodies are frozen"
    );
    Ok(Ok(frozen))
}

impl ShadowRequestDigest {
    /// The digest of the copy of its request `capsule` keeps: the request as
    /// sent, or its masked copy as stored; `None` for a request the wall
    /// withheld (FIX 6254).
    #[must_use]
    pub fn of_capsule(capsule: &StepReplayCapsule) -> Option<Self> {
        match &capsule.request {
            CapsuleRequest::Kept { stored_hash, .. } if *stored_hash == capsule.request_hash => {
                Some(Self::AsSent(capsule.request_hash))
            }
            CapsuleRequest::Kept { stored_hash, .. } => Some(Self::AsStored(*stored_hash)),
            CapsuleRequest::Withheld { .. } => None,
        }
    }
}
