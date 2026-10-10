//! Shadow mode: before a generated program runs, it is type-checked against
//! the declarations its prompt teaches. The report is recorded beside the
//! step and traced with the step's outcome. Nothing is blocked: the program
//! runs exactly as it would unchecked.

use super::host::executor_declarations;
use super::types::EngineExecutorStatus;
use crate::entity_id::EntityId;
use oneiron_code_check::{
    BackendId, CheckFailure, CheckInput, CheckReport, ShadowCheck, StepThen,
};
use serde_json::json;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::time::{Duration, Instant};

/// One step's shadow check. Dropping it counts and traces the check, with
/// the step taken as failed unless [`Self::ended`] says otherwise, so every
/// way out of a step is counted.
pub(super) struct ShadowStep<'a> {
    shadow: &'a ShadowCheck,
    run_id: EntityId,
    seq: u64,
    /// The configured checker, which a failure is recorded against.
    backend: BackendId,
    result: Result<CheckReport, CheckFailure>,
    elapsed: Duration,
    then: StepThen,
}

impl<'a> ShadowStep<'a> {
    pub(super) fn check(
        shadow: &'a ShadowCheck,
        run_id: EntityId,
        seq: u64,
        program: &str,
    ) -> Self {
        let declarations = executor_declarations();
        let started = Instant::now();
        // A checker that panics is a crashed check; the step runs on.
        let checked = catch_unwind(AssertUnwindSafe(|| {
            let checker = shadow.checker();
            let result = checker.check(&CheckInput {
                declarations: &declarations,
                program,
            });
            (checker.backend(), result)
        }));
        let (backend, result) = checked.unwrap_or_else(|_| {
            let backend = BackendId {
                name: "unknown",
                pin: String::new(),
            };
            (backend, Err(CheckFailure::Crashed))
        });
        Self {
            shadow,
            run_id,
            seq,
            backend,
            result,
            elapsed: started.elapsed(),
            then: StepThen::Failed,
        }
    }

    /// The step's record: what the check found, or why it found nothing.
    pub(super) fn record(&self) -> String {
        let backend = match &self.result {
            Ok(report) => &report.backend,
            Err(_) => &self.backend,
        };
        let mut record = json!({
            "schema_version": 1,
            "mode": "shadow",
            "backend": backend.name,
            "pin": backend.pin,
            "elapsed_us": u64::try_from(self.elapsed.as_micros()).unwrap_or(u64::MAX),
        });
        match &self.result {
            Ok(report) => {
                record["diagnostics"] = json!(report.diagnostics);
                record["peak_memory_bytes"] = json!(report.peak_memory_bytes);
            }
            Err(failure) => record["failure"] = json!(failure.code()),
        }
        record.to_string()
    }

    /// How the step ended: the run's status when it stopped there, or none
    /// when another step follows. A step that returns no outcome stays
    /// failed.
    pub(super) fn ended(&mut self, status: Option<&EngineExecutorStatus>) {
        self.then = match status {
            Some(EngineExecutorStatus::Complete) => StepThen::Completed,
            Some(EngineExecutorStatus::Waiting(_)) => StepThen::Waiting,
            _ => StepThen::Continued,
        };
    }
}

impl Drop for ShadowStep<'_> {
    fn drop(&mut self) {
        let totals = self
            .shadow
            .metrics()
            .observe(&self.result, self.elapsed, self.then);
        let (backend, codes, failure) = match &self.result {
            Ok(report) => (
                report.backend.name,
                report
                    .diagnostics
                    .iter()
                    .map(|diagnostic| diagnostic.code.to_string())
                    .collect::<Vec<_>>()
                    .join(","),
                "",
            ),
            Err(failure) => (self.backend.name, String::new(), failure.code()),
        };
        tracing::info!(
            target: "oneiron::code_check",
            run_id = %self.run_id.to_hex(),
            step = self.seq,
            backend,
            elapsed_us = u64::try_from(self.elapsed.as_micros()).unwrap_or(u64::MAX),
            codes = %codes,
            failure,
            then = self.then.as_str(),
            checked = totals.checked,
            with_diagnostics = totals.with_diagnostics,
            then_with_diagnostics = ?totals.then_with_diagnostics,
            then_clean = ?totals.then_clean,
            codes_seen = ?totals.codes,
            unchecked = ?totals.unchecked,
            latency = ?totals.latency.get(backend),
            "code-mode program checked in shadow mode"
        );
    }
}
