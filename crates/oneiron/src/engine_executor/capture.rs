//! The executor's step replay capture (FIX 3028, FIX 3694): each step of a
//! leased attempt's canonical run, captured as it is about to be sent, with
//! the run's state before the step. Once the step ran, its checkpoint
//! commits the step's replay context beside that capture (FIX 6351): the
//! guest responses its host handed out, what its result reads saw of reader
//! state (FIX 6352), and where its calls end (FIX 6354).

use super::continuation::continuation_note;
use super::driver::EngineNativeExecutor;
use super::record::{StepEnd, completed_step_count};
use super::store::{RUN_SIGNALS_OUTPUT_SUFFIX, TURN_INTERRUPTS_OUTPUT_SUFFIX};
use super::types::{EngineExecutorConfig, EngineExecutorResult};
use crate::code_run::{
    CapsuleHost, CodeRunRawOutput, CodeRunReplayRecord, ConsoleSlot, ExecutorStorage, FoldWordRef,
    StepCapture, StepContextCapture, StepContextCommit, StepReplayContext, StepStartCapture,
    capture_step, push_fold_word, recorded_fold_words,
};
use crate::{EntityId, Error, LlmRequest};

impl EngineNativeExecutor<'_> {
    /// The complete rows this step's request was read from, or `None` when
    /// any constituent lacks a witness (FIX 6999). A task its host declared
    /// the caller's own text names no row (FIX 7087); a task its host built,
    /// the signals a leased branch delivered and a continuation's note stay
    /// unknown today. The other sets are real witnesses, ready for their
    /// later carriers to complete the union. The self brief the request
    /// carries brings the rows its host listed beside it (FIX 17594), and a
    /// request with none brings none. Host data a backend adds after the
    /// request, as the browser planner's handoff is, is not in this set: the
    /// backend names no rows for a call it adds any to.
    pub(super) fn step_source_rows(
        &self,
        config: &EngineExecutorConfig,
        record: &CodeRunReplayRecord,
    ) -> Option<Vec<EntityId>> {
        // FIX 7087: a task its host declared the caller's own, byte for
        // byte, as an MCP `execute_code` caller's is, no row of the vault
        // wrote. Engine 03:58: claimed.task plus executor_config is
        // host-built, not source-free, so every other task stays unknown, a
        // declared one its host added to included. Skill additions do not
        // witness the host text itself.
        let host_task_rows = self
            .gated_write
            .declared_caller_task(config.run_id)
            .filter(|task| *task == config.task)
            .map(|_| Vec::new());
        let exposure_rows = if self.gated_write.run_write_token().is_none() {
            Some(Vec::new())
        } else {
            self.gated_write
                .replay_capture()
                .and_then(|(attempt, _, exposures)| {
                    (attempt.as_bytes() == config.run_id.as_bytes()).then(|| {
                        exposures
                            .iter()
                            .map(|exposure| exposure.skill)
                            .collect::<Vec<_>>()
                    })
                })
        };
        let bridge_rows = crate::code_run::resident_tool_answer_rows(record, None);
        let epoch_rows = self.compaction_epochs(config.run_id).ok().map(|frames| {
            frames
                .epochs
                .iter()
                .map(|(row, _)| row.summary_id())
                .collect::<Vec<_>>()
        });
        let brief_rows = Some(self.brief_source_rows());
        // The steers, messages and interrupts the run's branch delivered
        // (AGM-2), which its requests read back beside their steps and
        // turns, have no row witness yet. A run that kept none reads none.
        let signal_rows = (!holds_branch_signals(record)).then(Vec::new);
        // An approved continuation's note (FIX 3694) has no row witness
        // yet. A run with no note reads none.
        let continuation_rows = match continuation_note(&self.storage, config.run_id) {
            Ok(None) => Some(Vec::new()),
            Ok(Some(_)) | Err(_) => None,
        };
        // The records each fold summary the request copies was written from
        // (FIX 18924).
        let fold_rows = Some(
            self.step_fold_words(record)
                .into_iter()
                .flat_map(|word| word.sources)
                .collect::<Vec<_>>(),
        );
        crate::skill_optimize::union_source_rows([
            host_task_rows,
            exposure_rows,
            bridge_rows,
            epoch_rows,
            brief_rows,
            signal_rows,
            continuation_rows,
            fold_rows,
        ])
    }

    /// The folds whose accepted summaries this step's request copies (FIX
    /// 18924): each stub the request shows with its summary, and each fold
    /// answer `record` records, which a step's console may print. Known
    /// dependencies only: unknown inputs stay with `step_source_rows`.
    fn step_fold_words(&self, record: &CodeRunReplayRecord) -> Vec<FoldWordRef> {
        let mut words = self.request_fold_words.clone();
        for word in recorded_fold_words(&record.bridge_calls) {
            push_fold_word(&mut words, word);
        }
        words
    }

    /// Records each of `outputs`, which run `record`'s step just published,
    /// as a dependent of the records whose words the run's fold answers
    /// copy (FIX 18924): a step's observation, console and files may print
    /// any answer its program holds. Known dependency edges only, apart
    /// from each output's input rows.
    pub(super) fn record_step_fold_dependents(
        &self,
        record: &CodeRunReplayRecord,
        outputs: &[&CodeRunRawOutput],
    ) -> EngineExecutorResult<()> {
        let mut sources: Vec<EntityId> = recorded_fold_words(&record.bridge_calls)
            .into_iter()
            .flat_map(|word| word.sources)
            .collect();
        sources.sort_unstable();
        sources.dedup();
        for output in outputs {
            self.storage
                .record_code_run_fold_sources(record.run_id, output, &sources)?;
        }
        Ok(())
    }

    /// Captures `request` before it is sent, with `console`, where it shows
    /// the step before's console whole (FIX 3608), and `record`, the run's row as
    /// it stands before the step, and the config and teaching fingerprint it
    /// runs under, when the run is a leased attempt's own canonical run (the
    /// run whose id is the attempt's). Step 0's request is the one input no
    /// answer of the run has touched yet, which a contribution check
    /// regenerates; each step's start is what a continuation of a failed run
    /// forks from. An off-record run, a host action's or reader child's run
    /// and a run no lease binds capture nothing, and a capture that fails
    /// leaves no capsule and never fails the step.
    ///
    /// Whatever binds a canonical run, its dispatcher is first handed the
    /// request and the task (FIX 2343): a blocked report the step's program
    /// files keeps them for its code fix, so a run no lease binds replays
    /// too.
    pub(super) fn capture_step_start(
        &self,
        config: &EngineExecutorConfig,
        step: u64,
        request: &LlmRequest,
        console: Option<ConsoleSlot>,
        record: &CodeRunReplayRecord,
        prompt_fingerprint: &str,
    ) {
        let ExecutorStorage::Canonical(vault) = &self.storage else {
            return;
        };
        self.gated_write.observe_run_request(request, &config.task);
        let Some((attempt, lease_generation, exposures)) = self.gated_write.replay_capture() else {
            return;
        };
        if config.run_id.as_bytes() != attempt.as_bytes() {
            return;
        }
        let source_rows = self.step_source_rows(config, record);
        let fold_words = self.step_fold_words(record);
        capture_step(
            vault,
            &StepCapture {
                attempt,
                lease_generation,
                run: config.run_id,
                step,
                host: CapsuleHost::EngineStep,
                actor: self.gated_write.actor(),
                request,
                task: &config.task,
                exposures,
                console,
                source_rows,
                fold_words,
                start: Some(StepStartCapture {
                    record,
                    model: &config.model,
                    model_locality: config.model_locality,
                    seat_effort: config.seat_effort,
                    global_tier: &config.global_tier,
                    soft_steps: config.limits.soft_steps,
                    prompt_fingerprint,
                }),
            },
        );
    }

    /// The replay context of the step `record` is about to checkpoint, whose
    /// calls are its bridge rows from `bridge_start` on, with what its host
    /// kept in `capture`: the responses it handed out (FIX 6351), what its
    /// result reads saw of reader state (FIX 6352), the callables its
    /// program called that answered and the skill bodies calls' answers
    /// delivered to it (FIX 3608). Beside them, where its
    /// checkpoint says its calls end (FIX 6354): the end and the
    /// context's digest, which the checkpoint binds, and the context as the
    /// checkpoint commits it. Only a leased attempt's own canonical run
    /// captures its steps ([`Self::capture_step_start`]), so only its
    /// context names a capsule.
    pub(super) fn step_context(
        &self,
        config: &EngineExecutorConfig,
        record: &CodeRunReplayRecord,
        bridge_start: usize,
        capture: StepContextCapture,
    ) -> EngineExecutorResult<(StepEnd, StepContextCommit)> {
        let position = |at: usize| {
            u64::try_from(at).map_err(|_| Error::ArithmeticOverflow("executor bridge position"))
        };
        let bridge_end = position(record.bridge_calls.len())?;
        let capsule = matches!(self.storage, ExecutorStorage::Canonical(_))
            .then(|| self.gated_write.replay_capture())
            .flatten()
            .filter(|(attempt, _, _)| attempt.as_bytes() == config.run_id.as_bytes())
            .map(|(_, lease_generation, _)| (config.run_id, lease_generation));
        // FIX 18924: the fold answers a hook view the guest read shows.
        let fold_words = capture
            .guest_responses
            .viewed_fold_words(&record.bridge_calls);
        let context = StepReplayContext {
            run: config.run_id,
            step: completed_step_count(record)?,
            bridge_start: position(bridge_start)?,
            bridge_end,
            guest_responses: capture.guest_responses,
            reader_reads: capture.reader_reads,
            callables: capture.callables,
            deliveries: capture.deliveries,
        };
        let commit = StepContextCommit::new(capsule, context, fold_words)?;
        let end = StepEnd {
            bridge_end,
            context: commit.digest(),
        };
        Ok((end, commit))
    }
}

/// Whether `record` keeps steers, messages or interrupts its branch
/// delivered (AGM-2), which every later request of the run reads back.
fn holds_branch_signals(record: &CodeRunReplayRecord) -> bool {
    record.outputs.iter().any(|output| {
        output.path.ends_with(RUN_SIGNALS_OUTPUT_SUFFIX)
            || output.path.ends_with(TURN_INTERRUPTS_OUTPUT_SUFFIX)
    })
}
