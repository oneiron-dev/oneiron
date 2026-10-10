//! Shadow mode: before a generated program runs, it is type-checked against
//! the declarations its prompt teaches. The report is recorded beside the
//! step and traced with the step's outcome. Nothing is blocked: the program
//! runs exactly as it would unchecked.

use super::host::executor_declarations;
use crate::entity_id::EntityId;
use oneiron_code_check::{CheckFailure, CheckInput, CheckReport, ShadowCheck, StepThen};
use serde_json::json;
use std::time::{Duration, Instant};

/// One step's shadow check. Dropping it counts and traces the check, with
/// the step taken as failed unless [`Self::then`] says otherwise, so every
/// way out of a step is counted.
pub(super) struct ShadowStep<'a> {
    shadow: &'a ShadowCheck,
    run_id: EntityId,
    seq: u64,
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
        let result = shadow.checker().check(&CheckInput {
            declarations: &declarations,
            program,
        });
        Self {
            shadow,
            run_id,
            seq,
            result,
            elapsed: started.elapsed(),
            then: StepThen::Failed,
        }
    }

    /// The step's record: what the check found, or why it found nothing.
    pub(super) fn record(&self) -> String {
        let backend = match &self.result {
            Ok(report) => report.backend.clone(),
            Err(_) => self.shadow.checker().backend(),
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

    /// What the step did after its check.
    pub(super) fn then(&mut self, then: StepThen) {
        self.then = then;
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
            Err(failure) => (
                self.shadow.checker().backend().name,
                String::new(),
                failure.code(),
            ),
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
