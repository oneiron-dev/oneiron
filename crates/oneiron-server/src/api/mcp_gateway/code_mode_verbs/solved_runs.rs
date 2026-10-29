//! A code-mode run's solved-run capture (CUA E8a; DESIGN-2 "The Coach",
//! row E8). After a browser call, under the seat lock the call holds and
//! before the run's planner hears how it ended, a source that names its
//! checks and its recorded task type has those checks read again on the
//! page it left, and the span that reached that page is kept as the
//! caller's evidence through the caller's own capture door, under the host
//! origin the call came in on.
//!
//! The sources that do today are a library run of a filed program that met
//! its filled postcondition, its type and subgoal the program record's, and
//! an agent's TASK run that ended (CUA E8b), its checks and question its
//! TASK's done-means and its type the run's recorded stamp.
//! A draft names its checks but no recorded type, and a raw batch names
//! neither, so they capture nothing and say why in the log. A capture that
//! fails is logged with its cause and never fails the call.

use super::*;
use oneiron::browser_library::{SolvedCaptureReceipt, SolvedRunCapture, SolvedSource, workflow};
use oneiron::learning::TypeRef;
use oneiron::task_verb::DoneMeans;
use oneiron_browser::{
    DraftInput, ExpectInput, LibraryRunInput, SOLVED_PAST_PRESS, SubgoalStatus, filled_checks,
};

/// A browser call's caller, for what the call solved.
pub(super) struct BrowserCapture<'a, 'v> {
    pub(super) vault: &'a oneiron::Vault,
    pub(super) memory: &'a Memory<'v>,
    pub(super) origin: &'a HostWriteOrigin,
    pub(super) run_id: oneiron::EntityId,
}

/// What a source names for its capture (CUA E8a): the checks the page
/// must meet, the exact subgoal, the recorded task type, where they came
/// from, and the history entry its span starts after.
pub(super) struct CheckedSpan {
    pub(super) subgoal: String,
    pub(super) checks: Vec<ExpectInput>,
    pub(super) type_ref: TypeRef,
    pub(super) source: SolvedSource,
    pub(super) after_seq: Option<u64>,
}

impl BrowserCapture<'_, '_> {
    /// Keeps what `verb`'s call with `input` reached on `session` (its
    /// answer `output`, its history's latest entry before it `mark`), as
    /// the caller's evidence, when it names its checks and type. Logs what
    /// it came to; never fails the call. A capture that failed gives its
    /// caller a note for the call's answer (FIX 10509, the
    /// `solved_capture` note); anything else gives none.
    pub(super) fn after_call(
        &self,
        session: &mut BrowserSession,
        verb: AgentVerb,
        input: &Value,
        output: &Value,
        mark: Option<u64>,
    ) -> Option<String> {
        let span = match checked_span(self.vault, verb, input, output, mark) {
            Ok(Some(span)) => span,
            Ok(None) => return None,
            Err(cause) => {
                tracing::info!(verb = verb.as_str(), %cause, "browser call captured no solved run");
                return None;
            }
        };
        match self.capture_checked_run(session, span) {
            Ok(note) => {
                tracing::info!(verb = verb.as_str(), %note, "browser solved-run capture");
                None
            }
            Err(cause) => {
                tracing::warn!(verb = verb.as_str(), %cause, "browser solved-run capture failed");
                Some(format!("solved-run capture failed: {cause}"))
            }
        }
    }

    /// Reads `span`'s checks on `session`'s page, drafts the span that
    /// reached it, and keeps it through the caller's capture door when it
    /// is solved: what it came to, or why it failed.
    pub(super) fn capture_checked_run(
        &self,
        session: &mut BrowserSession,
        span: CheckedSpan,
    ) -> Result<String, String> {
        let input = DraftInput {
            subgoal: span.subgoal.clone(),
            postcondition: span.checks,
            after_seq: span.after_seq,
            // A span its goal reached before a granted press ends there
            // (FIX 10511), not on the press.
            through_seq: session.pre_press_through(span.after_seq),
            past_press: SOLVED_PAST_PRESS,
        };
        let snapshot = session
            .snapshot_solved_run(input)
            .map_err(|error| format!("snapshot: {error}"))?;
        if let Some(gap) = &snapshot.gap {
            return Ok(format!("not solved: {gap:?}"));
        }
        let (Some(site), Some(origin)) =
            (snapshot.draft.site.clone(), snapshot.draft.origin.clone())
        else {
            return Ok("not solved: the span has no site or origin".to_owned());
        };
        let capture = SolvedRunCapture {
            run_id: self.run_id,
            call_id: self.memory.invocation(),
            site,
            origin,
            type_ref: span.type_ref,
            subgoal: span.subgoal,
            checks: snapshot.checks,
            draft: snapshot.draft,
            secret_slots: snapshot.secret_slots,
            replay_ready: snapshot.replay_ready,
            source: span.source,
            captured_at_ms: self.vault.now_recorded_ms(),
        };
        let receipt = self
            .memory
            .capture_browser_solved_run(self.origin.clone(), capture)
            .map_err(|error| format!("capture door: {error}"))?;
        Ok(match receipt {
            SolvedCaptureReceipt::Captured { id, fresh, .. } => {
                format!("captured {} (fresh: {fresh})", id.to_hex())
            }
            SolvedCaptureReceipt::Unavailable(gap) => format!("unavailable: {gap:?}"),
        })
    }
}

/// The subgoal a TASK run's solved span is grouped under (CUA E8b, CALLS
/// row "TASK-run subgoal"): its done-means' question, exactly.
fn task_run_subgoal(goal: &DoneMeans) -> String {
    goal.question.clone()
}

impl RunGuests {
    /// Keeps what this run's browser reached for TASK `task` as the
    /// caller's solved-run evidence (CUA E8b; the E8 pair trigger): the
    /// done-means' browser checks read again on the page the run left,
    /// under its seat lock, the span from the run's first act, grouped under
    /// the run's recorded type and the done-means' question. A goal that
    /// names no browser check, or a run whose browser never started,
    /// captures nothing. Logs what it came to; never fails the run.
    pub(crate) fn capture_task_run(
        &self,
        server: &SyncServer,
        memory: &Memory<'_>,
        origin: &HostWriteOrigin,
        task: oneiron::EntityId,
        type_ref: TypeRef,
        goal: &DoneMeans,
    ) {
        if goal.browser_checks.is_empty() {
            tracing::info!("a TASK run's done-means names no browser check; no solved run kept");
            return;
        }
        let Some(run) = &self.browser else {
            return;
        };
        let mut session = run.session.lock().unwrap_or_else(PoisonError::into_inner);
        let Some(driver) = session.as_mut() else {
            tracing::info!("a TASK run's browser never started; no solved run kept");
            return;
        };
        let capture = BrowserCapture {
            vault: &server.vault,
            memory,
            origin,
            run_id: run.run_id,
        };
        let span = CheckedSpan {
            subgoal: task_run_subgoal(goal),
            checks: goal.browser_checks.clone(),
            type_ref,
            source: SolvedSource::TaskRun { task },
            after_seq: None,
        };
        match capture.capture_checked_run(driver, span) {
            Ok(note) => tracing::info!(%note, "TASK run solved-run capture"),
            Err(cause) => tracing::warn!(%cause, "TASK run solved-run capture failed"),
        }
    }
}

/// What `verb`'s call names for a capture: none for a call that solved no
/// span; why not, for a source that names no recorded type or checks.
fn checked_span(
    vault: &oneiron::Vault,
    verb: AgentVerb,
    input: &Value,
    output: &Value,
    mark: Option<u64>,
) -> Result<Option<CheckedSpan>, String> {
    match verb {
        AgentVerb::SelfBrowserLibraryRun => {
            let done = output
                .get("status")
                .and_then(|status| serde_json::from_value::<SubgoalStatus>(status.clone()).ok());
            if done != Some(SubgoalStatus::Done) {
                return Ok(None);
            }
            let input: LibraryRunInput = serde_json::from_value(input.clone())
                .map_err(|error| format!("library run input: {error}"))?;
            let id = oneiron::EntityId::from_hex(&input.workflow)
                .map_err(|_| "library run names no program id".to_owned())?;
            let record = workflow(vault, id)
                .map_err(|error| format!("library record: {error}"))?
                .ok_or_else(|| "the program ran is filed no more".to_owned())?;
            let checks = filled_checks(&record.program, &input)
                .map_err(|error| format!("filled checks: {error}"))?;
            Ok(Some(CheckedSpan {
                subgoal: record.program.subgoal,
                checks,
                type_ref: record.type_ref,
                source: SolvedSource::LibraryRun { workflow: id },
                after_seq: mark,
            }))
        }
        AgentVerb::SelfBrowserLibraryDraft => {
            Err("a draft names its checks but no recorded task type".to_owned())
        }
        _ => Ok(None),
    }
}
