//! The executor's step replay capture (FIX 3028, FIX 3694): each step of a
//! leased attempt's canonical run, captured as it is about to be sent, with
//! the run's state before the step.

use super::driver::EngineNativeExecutor;
use super::types::EngineExecutorConfig;
use crate::code_run::{
    CapsuleHost, CodeRunReplayRecord, ExecutorStorage, StepCapture, StepStartCapture, capture_step,
};
use crate::{EntityId, LlmRequest};

impl EngineNativeExecutor<'_> {
    /// The complete rows this step's request was read from, or `None` when
    /// any constituent lacks a witness (FIX 6999). The host-built task and
    /// browser-handoff evidence stay unknown today; the other sets are real
    /// witnesses, ready for their later carriers to complete the union.
    pub(super) fn step_source_rows(
        &self,
        config: &EngineExecutorConfig,
        record: &CodeRunReplayRecord,
    ) -> Option<Vec<EntityId>> {
        // Engine 03:58: claimed.task plus executor_config is host-built, not
        // source-free. Skill additions do not witness the host text itself.
        let host_task_rows: Option<Vec<EntityId>> = None;
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
        // Browser planner handoff evidence has no row witness yet (FIX 6999).
        let browser_rows: Option<Vec<EntityId>> = None;
        crate::skill_optimize::union_source_rows([
            host_task_rows,
            exposure_rows,
            bridge_rows,
            epoch_rows,
            browser_rows,
        ])
    }

    /// Captures `request` before it is sent, with `record`, the run's row as
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
                source_rows,
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
}
