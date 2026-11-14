//! A step its deadline stopped (FIX 7703). The step parks as its run's
//! pending step: the calls its program made and their answers are kept in
//! the record's bridge log, and nothing calls the program complete. The
//! run's next entry runs the same stored program again before any new model
//! turn: the recorded calls answer from their rows, and only past the
//! step's frontier does a call run live. A program that does not meet its
//! recorded calls holds, and the entry commits nothing.
//! A pure-JS stretch longer than the step's allowance starts again from the
//! program's top on each entry, so it is not guaranteed to finish: no
//! larger allowance, retry count or default is added for it.
//! Entry: `EngineNativeExecutor::take_pending_program`.
//! `PendingCodeStep` is defined by `code_run`; the replay of its calls by
//! `engine_executor::host`.

use super::super::host::DeadlineReplay;
use super::super::host::resume_preflight::ResumePreflightReport;
use super::super::store::SCRIPT_OUTPUT_DIR;
use super::*;
use crate::code_run::{ExecutorWireRepairs, PendingCodeStep};
use crate::code_sandbox::SandboxBoundaryContract;
use crate::store::result_manifest::invalid_code_run_replay;

const FRONTIER_MOVED: &str = "the run's record moved past its pending step's frontier";
const DETERMINISM_CHANGED: &str = "the pending step's frozen clock or RNG seed changed";
const SCRIPT_CHANGED: &str = "the pending step's stored program changed";

/// What a pending step taken off its run's record runs in this entry: the
/// program it runs again, and the replay of the calls it already made.
pub(super) struct ResumedProgram<'p> {
    pub(super) program: StepProgram<'p>,
    pub(super) replay: DeadlineReplay,
    /// Whether the guest boundary changed since the step parked: a preflight flag (L8-23).
    pub(super) boundary_changed: bool,
}

/// How a deadline slice ends that parks: its status, and the preflight report of the pending
/// step it resumed, when it resumed one (L8-23).
pub(super) struct DeadlineSliceEnd {
    pub(super) status: EngineExecutorStatus,
    pub(super) resume_preflight: Option<ResumePreflightReport>,
}

/// What a park keeps of the program a step ran (FIX 7703).
pub(super) struct SliceProgram<'p> {
    /// The step's seq.
    pub(super) seq: u64,
    /// The step's first bridge position.
    pub(super) bridge_start: usize,
    pub(super) request_hash: [u8; 32],
    pub(super) script_blake3: [u8; 32],
    pub(super) prepared_identity: Option<[u8; 32]>,
    pub(super) guest_abi: [u8; 32],
    pub(super) trailing_speak: Option<&'p str>,
    /// The repairs the normalization made to the reply that wrote the
    /// program.
    pub(super) repairs: ExecutorWireRepairs,
    /// The model id that reply's served receipt named, when it named one.
    pub(super) answered_by: Option<ModelId>,
    /// The pending step this entry resumed, when it did.
    pub(super) prior: Option<&'p PendingCodeStep>,
    /// Whether the runtime answered the step with an outcome.
    pub(super) ran: bool,
    /// Whether the entry's root was cancelled.
    pub(super) cancelled: bool,
}

/// The trailing speech of a pending step's model reply, kept beside its
/// program until the step commits.
fn pending_speech_output_path(seq: u64) -> String {
    format!("{SCRIPT_OUTPUT_DIR}/{seq:06}.pending-speech.txt")
}

/// The digest of the guest boundary a step's program runs against: its WIT
/// world and the imports it links, in their order (FIX 7703).
pub(super) fn guest_abi_digest(boundary: &SandboxBoundaryContract) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key("oneiron code-run pending step guest abi v1");
    hasher.update(boundary.wit_world().as_bytes());
    for import in boundary.linked_imports() {
        hasher.update(&[0]);
        hasher.update(import.name().as_bytes());
    }
    *hasher.finalize().as_bytes()
}

/// Whether a resumed step's program prepares to other JavaScript than the program its
/// pending step ran (FIX 8276, FIX 7703): a preflight flag, no longer a refusal (L8-23).
pub(super) fn pending_preparation_changed(
    pending: &PendingCodeStep,
    prepared: &PreparedSource<'_>,
) -> bool {
    prepared.transpiled().map(TranspiledSource::identity) != pending.prepared_identity
}

impl EngineNativeExecutor<'_> {
    /// The program of `pending`, the pending step the caller took off
    /// `record` (FIX 7703): its stored program, checked against the step
    /// (its position, frontiers, frozen clock and RNG seed, and program
    /// digest), and the rows its program made, taken off the record so the
    /// step's next commit writes them again with the rest of its calls. A
    /// changed guest boundary is a preflight flag, not a refusal (L8-23).
    /// The record holds no pending step from here: that commit, whatever it
    /// is, replaces the stored one under the record's generation. A step that
    /// does not check out holds: the entry fails with the replay error and
    /// commits nothing, so the stored step, its rows and its frontier stay as
    /// they were. The entry's own lease, seat and storage binding checks ran
    /// before this.
    ///
    /// The program carries the correction record of the reply that wrote
    /// it, with the model, answering model and repairs its pending step
    /// keeps: the record commits once, with the checkpoint the resumed step
    /// commits, and the reply's heal tally moves in that commit (FIX 4411).
    pub(super) fn take_pending_program<'p>(
        &self,
        config: &EngineExecutorConfig,
        record: &mut CodeRunReplayRecord,
        boundary: &SandboxBoundaryContract,
        pending: &'p PendingCodeStep,
    ) -> EngineExecutorResult<ResumedProgram<'p>> {
        let (Ok(bridge_start), Ok(bridge_frontier), Ok(output_frontier)) = (
            usize::try_from(pending.bridge_start),
            usize::try_from(pending.bridge_frontier),
            usize::try_from(pending.output_frontier),
        ) else {
            return Err(invalid_code_run_replay(FRONTIER_MOVED).into());
        };
        if pending.step_seq != completed_step_count(record)?
            || bridge_start > bridge_frontier
            || record.bridge_calls.len() != bridge_frontier
            || record.outputs.len() != output_frontier
        {
            return Err(invalid_code_run_replay(FRONTIER_MOVED).into());
        }
        if pending.determinism != config.determinism {
            return Err(invalid_code_run_replay(DETERMINISM_CHANGED).into());
        }
        let boundary_changed = pending.guest_abi != guest_abi_digest(boundary);
        // Once an erase of the run's actor took its replies (FIX 5718), the
        // step's rows answer nothing, and nothing is sent again.
        if self.storage.code_run_response_erased(record.run_id)? {
            return Err(crate::code_run::response_erased_error("a pending step's resume").into());
        }
        let script =
            load_utf8_output(&self.storage, record, &script_output_path(pending.step_seq))?;
        if *blake3::hash(script.as_bytes()).as_bytes() != pending.script_blake3 {
            return Err(invalid_code_run_replay(SCRIPT_CHANGED).into());
        }
        let trailing_speak = if pending.trailing_speech {
            Some(load_utf8_output(
                &self.storage,
                record,
                &pending_speech_output_path(pending.step_seq),
            )?)
        } else {
            None
        };
        let rows = record.bridge_calls.split_off(bridge_start);
        record.invalidate_verb_rows();
        Ok(ResumedProgram {
            replay: DeadlineReplay::new(
                rows,
                pending.guest_calls.clone(),
                config.run_id,
                pending.step_seq,
                pending.bridge_frontier,
            ),
            boundary_changed,
            program: StepProgram {
                request_hash: pending.request_hash,
                script,
                trailing_speak,
                repairs: pending.repairs,
                correction: CodeRunCorrectionDraft::accepted(
                    config.run_id,
                    pending.step_seq,
                    &pending.model,
                    pending.repairs,
                )
                .answered_by(pending.answered_by.clone()),
                // A stored program makes no model turn, so it takes no
                // interrupt; its step boundary takes the pending ones.
                interrupts: crate::engine_executor::run_signals::TakenSignals::default(),
            },
        })
    }

    /// How a slice of a step ends when its deadline or its replay decides
    /// it (FIX 7703); `None` for every other end, which the step takes as it
    /// always has (its program finished, failed, parked on a wait or
    /// declined its TASK), with a resumed step's rows whole in its host.
    ///
    /// A resumed program that did not meet its recorded calls holds, as
    /// does one whose walk turned dry: the entry fails with the replay error
    /// or the walk's report, or the cancel that stopped it, and commits
    /// nothing. A program that ended with recorded calls unreached drops a
    /// pure tail and commits, and holds an effect tail with the report
    /// (L8-23). A step its runtime stopped at its deadline parks.
    pub(super) fn end_deadline_slice(
        &self,
        config: &EngineExecutorConfig,
        record: &mut CodeRunReplayRecord,
        expected: Option<CodeRunReplayGeneration>,
        host: &mut RecordingJsHost<'_, '_>,
        slice: SliceProgram<'_>,
    ) -> EngineExecutorResult<Option<DeadlineSliceEnd>> {
        let cancelled = || Error::Code(crate::error::CodeError::CodeStepCancelled);
        if let Some(why) = host.pending_replay_held() {
            if slice.cancelled {
                return Err(cancelled().into());
            }
            return Err(invalid_code_run_replay(why).into());
        }
        if let Some(report) = host.dry_preflight_report() {
            if slice.cancelled {
                return Err(cancelled().into());
            }
            return Err(EngineExecutorError::ResumeDivergence(Box::new(report)));
        }
        if slice.ran && !slice.cancelled && host.parks_at_deadline() {
            let resume_preflight = host.pending_preflight_report();
            let status = self.park_pending_step(config, record, expected, host, slice)?;
            return Ok(Some(DeadlineSliceEnd {
                status,
                resume_preflight,
            }));
        }
        if host.pending_replay_unreached() {
            if slice.cancelled {
                return Err(cancelled().into());
            }
            if let Some(report) = host.effect_tail_preflight_report() {
                return Err(EngineExecutorError::ResumeDivergence(Box::new(report)));
            }
        }
        Ok(None)
    }

    /// Parks the step as the run's pending step (FIX 7703): its rows, its
    /// stored bodies and its callable rows join the record, under the
    /// existing custody, beside the step that names them, and the record is
    /// compared and put in one transaction. No checkpoint is written, no
    /// result is bound, and no output, console line or file of the slice is
    /// kept: the program makes them again when it runs again. So the park
    /// writes no correction record and moves no heal tally: the commit of
    /// the step's checkpoint does both, once (FIX 4411). A step parked again
    /// keeps its first park's request, program, speech, model, answering
    /// model, repairs and frontier start.
    fn park_pending_step(
        &self,
        config: &EngineExecutorConfig,
        record: &mut CodeRunReplayRecord,
        expected: Option<CodeRunReplayGeneration>,
        host: &mut RecordingJsHost<'_, '_>,
        slice: SliceProgram<'_>,
    ) -> EngineExecutorResult<EngineExecutorStatus> {
        let position = |at: usize| {
            u64::try_from(at).map_err(|_| Error::ArithmeticOverflow("executor bridge position"))
        };
        let callable_rows = host.result_rows();
        let (rows, guest_calls) = host.take_parked_calls();
        // A write the step already made is in its rows, so no later step
        // makes it again under a fresh receipt.
        self.gated_write.refuse_a_step_that_dropped_a_write(
            config.run_id,
            position(slice.bridge_start)?,
            &rows,
        )?;
        record.record_callable_rows(callable_rows);
        record.bridge_calls.extend(rows);
        record.outputs.append(&mut host.captured);
        let trailing_speech = match (slice.prior, slice.trailing_speak) {
            (Some(prior), _) => prior.trailing_speech,
            (None, Some(text)) => {
                record_text_output(
                    &self.storage,
                    record,
                    pending_speech_output_path(slice.seq),
                    text,
                )?;
                true
            }
            (None, None) => false,
        };
        record.pending_step = Some(PendingCodeStep {
            step_seq: slice.seq,
            bridge_start: position(slice.bridge_start)?,
            guest_calls,
            bridge_frontier: position(record.bridge_calls.len())?,
            output_frontier: position(record.outputs.len())?,
            script_blake3: slice.script_blake3,
            prepared_identity: slice.prepared_identity,
            guest_abi: slice.guest_abi,
            request_hash: slice.request_hash,
            model: slice
                .prior
                .map_or(&config.model, |prior| &prior.model)
                .clone(),
            answered_by: slice
                .prior
                .map_or(slice.answered_by, |prior| prior.answered_by.clone()),
            repairs: slice.prior.map_or(slice.repairs, |prior| prior.repairs),
            determinism: config.determinism,
            trailing_speech,
            park_generation: slice
                .prior
                .map_or(0, |prior| prior.park_generation.saturating_add(1)),
        });
        // A flaky commit converts to success on one identical retry (FIX
        // 1443); a first commit that actually landed fails the retry closed
        // on its generation mismatch instead.
        match self
            .storage
            .put_code_run_replay_record_if_generation(record, expected)
        {
            Err(error) if matches!(error, Error::Storage(_) | Error::MapFull) => {
                tracing::warn!("{error:?}: pending step commit hit a storage error; retrying once");
                self.storage
                    .put_code_run_replay_record_if_generation(record, expected)?;
            }
            result => {
                result?;
            }
        }
        // The same step, at the same seq: the run's next entry runs its
        // program again before any new model turn.
        Ok(EngineExecutorStatus::Yielded {
            next_step_seq: slice.seq,
        })
    }
}
