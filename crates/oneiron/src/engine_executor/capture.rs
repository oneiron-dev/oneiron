//! The executor's step replay capture (FIX 3028, FIX 3694): each step of a
//! leased attempt's canonical run, captured as it is about to be sent, with
//! the run's state before the step.

use super::driver::EngineNativeExecutor;
use super::types::EngineExecutorConfig;
use crate::LlmRequest;
use crate::code_run::{
    CapsuleHost, CodeRunReplayRecord, ExecutorStorage, StepCapture, StepStartCapture, capture_step,
};

impl EngineNativeExecutor<'_> {
    /// Captures `request` before it is sent, with `record`, the run's row as
    /// it stands before the step, and the config and teaching fingerprint it
    /// runs under, when the run is a leased attempt's own canonical run (the
    /// run whose id is the attempt's). Step 0's request is the one input no
    /// answer of the run has touched yet, which a contribution check
    /// regenerates; each step's start is what a continuation of a failed run
    /// forks from. An off-record run, a host action's or reader child's run
    /// and a run no lease binds capture nothing, and a capture that fails
    /// leaves no capsule and never fails the step.
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
        let Some((attempt, lease_generation, exposures)) = self.gated_write.replay_capture() else {
            return;
        };
        if config.run_id.as_bytes() != attempt.as_bytes() {
            return;
        }
        capture_step(
            vault,
            &StepCapture {
                attempt,
                lease_generation,
                run: config.run_id,
                step,
                host: CapsuleHost::EngineStep,
                request,
                task: &config.task,
                exposures,
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
