//! Shadow mode: before a generated program runs, it is type-checked against
//! the declarations its prompt teaches. The report is recorded beside the
//! step and traced with the step's outcome. Nothing is blocked: the program
//! runs exactly as it would unchecked. The record states the check's action
//! digest over the program, each declaration file and the checker at its pin
//! (OF-568).

use super::host::executor_declarations;
use super::store::{code_check_output_path, record_text_output};
use super::types::EngineExecutorStatus;
use crate::code_run::{CodeRunReplayGeneration, CodeRunReplayRecord, ExecutorStorage};
use crate::entity_id::EntityId;
use crate::receipt::{ActionInputs, call_bytes_digest};
use crate::session_overlay::RouteTarget;
use oneiron_code_check::{BackendId, CheckFailure, CheckInput, CheckReport, ShadowCheck, StepThen};
use serde_json::json;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::time::{Duration, Instant};

/// A step's report keeps at most this many diagnostics, each message cut at
/// this many bytes, so a report stays a few KiB however much tsc printed.
const RECORDED_DIAGNOSTICS: usize = 32;
const RECORDED_MESSAGE_BYTES: usize = 512;

/// The action a shadow check's digest names.
const SHADOW_CHECK_ACTION: &str = "code_check.shadow";

/// One step's shadow check. Dropping it counts and traces the check, with
/// the step taken as failed unless [`Self::ended`] says otherwise, so every
/// way out of a step is counted.
pub(super) struct ShadowStep<'a> {
    shadow: &'a ShadowCheck,
    run_id: EntityId,
    seq: u64,
    /// The configured checker, which a failure is recorded against.
    backend: BackendId,
    /// The check's action digest; `None` when the checker crashed before it
    /// named itself, so its pin is unknown.
    action_digest: Option<String>,
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
            shadow.checker().check_attributed(&CheckInput {
                declarations: &declarations,
                program,
            })
        }));
        let action_digest = checked.as_ref().ok().map(|(backend, _)| {
            declarations
                .iter()
                .fold(ActionInputs::new(), |inputs, file| {
                    inputs.with(file.name, call_bytes_digest(file.text.as_bytes()))
                })
                .with("checker", format!("{}@{}", backend.name, backend.pin))
                .action_digest(SHADOW_CHECK_ACTION, &call_bytes_digest(program.as_bytes()))
        });
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
            action_digest,
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
            "action_digest": self.action_digest,
            "elapsed_us": u64::try_from(self.elapsed.as_micros()).unwrap_or(u64::MAX),
        });
        match &self.result {
            Ok(report) => {
                // Bounded: the first diagnostics, each message cut short.
                let kept: Vec<_> = report
                    .diagnostics
                    .iter()
                    .take(RECORDED_DIAGNOSTICS)
                    .map(|diagnostic| {
                        let mut diagnostic = diagnostic.clone();
                        let cut = diagnostic
                            .message
                            .floor_char_boundary(RECORDED_MESSAGE_BYTES);
                        diagnostic.message.truncate(cut);
                        diagnostic
                    })
                    .collect();
                record["diagnostics_omitted"] = json!(report.diagnostics.len() - kept.len());
                record["diagnostics"] = json!(kept);
                record["peak_memory_bytes"] = json!(report.peak_memory_bytes);
            }
            Err(failure) => record["failure"] = json!(failure.code()),
        }
        record.to_string()
    }

    /// Appends the step's report to its record, after the step's own append
    /// at `generation`: the report never takes room the step needed, and
    /// one that cannot be stored is traced and dropped, the record left as
    /// the step committed it. Only the vault's own storage keeps reports: an
    /// off-record overlay is quota-bounded, and a discarding route keeps
    /// nothing.
    pub(super) fn append_report(
        &self,
        storage: &ExecutorStorage<'_>,
        record: &mut CodeRunReplayRecord,
        generation: CodeRunReplayGeneration,
    ) -> Option<CodeRunReplayGeneration> {
        if !matches!(
            storage.session_route_target(),
            None | Some(RouteTarget::Base)
        ) {
            return None;
        }
        let appended = record_text_output(
            storage,
            record,
            code_check_output_path(self.seq),
            &self.record(),
        )
        .and_then(|()| {
            storage
                .put_code_run_replay_record_if_generation_with_heal(record, Some(generation), None)
                .map_err(|error| {
                    record.outputs.pop();
                    error.into()
                })
        });
        match appended {
            Ok(generation) => Some(generation),
            Err(error) => {
                tracing::warn!(target: "oneiron::code_check", %error, "shadow check not recorded");
                None
            }
        }
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
