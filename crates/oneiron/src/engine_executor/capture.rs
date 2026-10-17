//! The executor's step replay capture (FIX 3028): the first step of a
//! leased attempt's canonical run, captured as it is about to be sent.

use super::driver::EngineNativeExecutor;
use super::types::EngineExecutorConfig;
use crate::LlmRequest;
use crate::code_run::{CapsuleHost, ExecutorStorage, StepCapture, capture_step};

impl EngineNativeExecutor<'_> {
    /// Captures `request` before it is sent when it is the first step of a
    /// leased attempt's own canonical run (the run whose id is the
    /// attempt's): the one input no answer of the run has touched yet. A
    /// later step, an off-record run, a host action's or reader child's run
    /// and a run no lease binds capture nothing, and a capture that fails
    /// leaves no capsule and never fails the step.
    pub(super) fn capture_first_step(
        &self,
        config: &EngineExecutorConfig,
        step: u64,
        request: &LlmRequest,
    ) {
        if step != 0 {
            return;
        }
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
            },
        );
    }
}
