//! Feedback mode (FIX 8277, owner ruling CODE-MODE-TS rule 4): each
//! generated program is type-checked as its author wrote it, against the
//! declarations its prompt teaches, on a thread of its own beside its run.
//! Nothing waits on a check: not the program, the step, the next model turn,
//! a reply or a drop. A step answers its check as it stands when the step
//! ends, landed or pending; a check that lands later writes its result under
//! the step's identity in the late-result store, never into the step's
//! replay record. A failed, crashed or unavailable check is a typed fact on
//! the step, never a refusal. The feedback states the check's action digest
//! over the program, its language, each declaration file and the checker at
//! its pin (OF-568).

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use oneiron_code_check::{
    BackendId, CheckFailure, CheckInput, CheckReport, Declaration, FeedbackCheck, ProgramLanguage,
    StepThen,
};

use super::store::{RESULT_REPLY_INLINE_BYTES, type_diagnostics_output_path, write_json};
use super::types::EngineExecutorStatus;
use crate::code_run::{
    CodeRunRawOutput, DiagnosticCollection, ExecutorStorage, FeedbackRoute, ProgramPreparationNote,
    ProgramStepFeedback, ProgramStepIdentity, StepKey, StoredStepFeedback, TYPE_CHECK_NOT_LOADED,
    TYPE_CHECK_NOT_STARTED, TYPE_CHECK_OFF, TypeCheckFacts, TypeDiagnostic, TypeDiagnostics,
    measure,
};
use crate::receipt::{ActionInputs, call_bytes_digest};
use crate::{EntityId, Vault};

mod publication;

/// The action a feedback check's digest names.
const FEEDBACK_CHECK_ACTION: &str = "code_check.feedback";

/// The host's type-feedback service: the configured checker, loaded off
/// every execution door, and the vault a landed check writes its result to.
/// One per served vault, shared by every run it serves.
#[derive(Clone)]
pub struct TypeFeedback {
    service: Arc<Service>,
}

struct Service {
    checker: Mutex<Checker>,
    /// Signalled once the checker's load ends.
    loaded: Condvar,
    /// The checker the configuration names, for a check pending its load.
    configured: String,
    /// Where a landed check writes its own result: the served vault's rows,
    /// or the live stretch of it a session-bound run was bound to.
    vault: Option<Arc<Vault>>,
}

enum Checker {
    Loading,
    Ready(Arc<FeedbackCheck>),
    Off,
    NotLoaded(CheckFailure),
}

impl TypeFeedback {
    /// A service whose `configured` checker is loading. A check admitted
    /// before the load ends waits for it on the check's own thread; its run
    /// never does. A check that lands writes its result to its step's row on
    /// its run's own route on `vault`: its rows, or the live stretch of it
    /// the run was bound to.
    #[must_use]
    pub fn loading(configured: &str, vault: Option<Arc<Vault>>) -> Self {
        Self::with(Checker::Loading, configured, vault)
    }

    /// A service with the check mode off: each step's feedback answers
    /// unavailable, and carries its preparation note.
    #[must_use]
    pub fn off() -> Self {
        Self::with(Checker::Off, "", None)
    }

    fn with(checker: Checker, configured: &str, vault: Option<Arc<Vault>>) -> Self {
        Self {
            service: Arc::new(Service {
                checker: Mutex::new(checker),
                loaded: Condvar::new(),
                configured: configured.to_owned(),
                vault,
            }),
        }
    }

    /// The checker's load ended: the checks waiting on it go on, checked by
    /// it or unavailable with its failure.
    pub fn loaded(&self, checker: Result<Arc<FeedbackCheck>, CheckFailure>) {
        *lock(&self.service.checker) = match checker {
            Ok(checker) => Checker::Ready(checker),
            Err(failure) => Checker::NotLoaded(failure),
        };
        self.service.loaded.notify_all();
    }

    /// Starts `job`'s check beside its program, on its own thread, and
    /// returns at once: nothing here waits on the checker or its load.
    pub(super) fn start(&self, job: CheckJob) -> StepCheck {
        let mut facts = TypeCheckFacts {
            language: job.language.as_str().to_owned(),
            file: job.language.file().to_owned(),
            backend: self.service.configured.clone(),
            pin: String::new(),
            action_digest: None,
            elapsed_us: None,
            peak_memory_bytes: None,
        };
        let now = match &*lock(&self.service.checker) {
            Checker::Off => Some(TypeDiagnostics::unavailable(TYPE_CHECK_OFF, None)),
            Checker::NotLoaded(failure) => Some(TypeDiagnostics::unavailable(
                TYPE_CHECK_NOT_LOADED,
                Some(failure.code().to_owned()),
            )),
            Checker::Ready(checker) => {
                let backend = checker.checker().backend();
                facts.backend = backend.name.to_owned();
                facts.pin = backend.pin;
                None
            }
            Checker::Loading => None,
        };
        let cell = Arc::new(StepCell::new(&job, facts));
        if let Some(diagnostics) = now {
            cell.land(Landed::settled(diagnostics), false);
            return StepCheck::of(cell);
        }
        let (service, working) = (Arc::clone(&self.service), Arc::clone(&cell));
        let started = std::thread::Builder::new()
            .name("type-check".into())
            .spawn(move || service.work(&working, &job));
        if started.is_err() {
            let diagnostics = TypeDiagnostics::unavailable(TYPE_CHECK_NOT_STARTED, None);
            cell.land(Landed::settled(diagnostics), false);
        }
        StepCheck::of(cell)
    }
}

impl Service {
    /// The checker, once its load ended; waits on this check's own thread.
    fn checker(&self) -> Result<Arc<FeedbackCheck>, TypeDiagnostics> {
        let mut held = lock(&self.checker);
        while matches!(*held, Checker::Loading) {
            held = self
                .loaded
                .wait(held)
                .unwrap_or_else(PoisonError::into_inner);
        }
        match &*held {
            Checker::Ready(checker) => Ok(Arc::clone(checker)),
            Checker::NotLoaded(failure) => Err(TypeDiagnostics::unavailable(
                TYPE_CHECK_NOT_LOADED,
                Some(failure.code().to_owned()),
            )),
            Checker::Off | Checker::Loading => {
                Err(TypeDiagnostics::unavailable(TYPE_CHECK_OFF, None))
            }
        }
    }

    /// One check, on its own thread: run, measured, its large collection
    /// kept in the run's body, landed in its cell, and written on its run's
    /// own route when the step already wrote it pending. A check of a
    /// stretch that closed while it waited for its checker is never run: its
    /// program goes with it. A failure to keep it is traced; the run it
    /// checked is never touched.
    fn work(&self, cell: &StepCell, job: &CheckJob) {
        let landed = match self.checker() {
            Ok(checker) => {
                if !self.still_kept(job) {
                    return;
                }
                let checked = check(&checker, job);
                let diagnostics = checked.type_diagnostics(cell.facts());
                let (diagnostics, body, finalized) = self.placed(job, diagnostics);
                Landed {
                    diagnostics,
                    body,
                    finalized,
                    observed: Some((checker, checked)),
                }
            }
            Err(diagnostics) => Landed::settled(diagnostics),
        };
        if let Some(row) = cell.land(landed, self.publishes(job)) {
            self.publish(job, &row);
        }
    }
}

/// One program's check, as its step starts it.
pub(super) struct CheckJob {
    pub(super) key: StepKey,
    /// The program as its author wrote it.
    pub(super) program: String,
    pub(super) language: ProgramLanguage,
    pub(super) note: Option<ProgramPreparationNote>,
    /// The actor the run runs as.
    pub(super) actor: Option<EntityId>,
    /// The step's stored program, whose marks a stored collection takes.
    pub(super) source: Option<CodeRunRawOutput>,
    /// The declaration files the program is checked against: those its
    /// door teaches it, owned by the check.
    pub(super) declarations: Vec<Declaration<'static>>,
    /// Where a check that lands after its step keeps its result: its run's
    /// own route (FIX 10389).
    pub(super) route: FeedbackRoute,
}

/// What one check answered.
struct Checked {
    backend: BackendId,
    result: Result<CheckReport, CheckFailure>,
    /// `None` when the checker crashed before it named itself.
    action_digest: Option<String>,
    elapsed: Duration,
}

/// Runs `job`'s check on `checker`. A checker that panics is a crashed
/// check.
fn check(checker: &FeedbackCheck, job: &CheckJob) -> Checked {
    let started = Instant::now();
    let checked = catch_unwind(AssertUnwindSafe(|| {
        checker.checker().check_attributed(&CheckInput {
            declarations: &job.declarations,
            program: &job.program,
            language: job.language,
        })
    }));
    let action_digest = checked.as_ref().ok().map(|(backend, _)| {
        job.declarations
            .iter()
            .fold(ActionInputs::new(), |inputs, file| {
                inputs.with(file.name, call_bytes_digest(file.text.as_bytes()))
            })
            .with("language", job.language.file())
            .with("checker", format!("{}@{}", backend.name, backend.pin))
            .action_digest(
                FEEDBACK_CHECK_ACTION,
                &call_bytes_digest(job.program.as_bytes()),
            )
    });
    let (backend, result) = checked.unwrap_or_else(|_| {
        let backend = BackendId {
            name: "unknown",
            pin: String::new(),
        };
        (backend, Err(CheckFailure::Crashed))
    });
    Checked {
        backend,
        result,
        action_digest,
        elapsed: started.elapsed(),
    }
}

impl Checked {
    /// The check as the step's feedback carries it, every diagnostic inline.
    fn type_diagnostics(&self, pending: &TypeCheckFacts) -> TypeDiagnostics {
        let backend = match &self.result {
            Ok(report) => &report.backend,
            Err(_) => &self.backend,
        };
        let check = TypeCheckFacts {
            backend: backend.name.to_owned(),
            pin: backend.pin.clone(),
            action_digest: self.action_digest.clone(),
            elapsed_us: Some(u64::try_from(self.elapsed.as_micros()).unwrap_or(u64::MAX)),
            peak_memory_bytes: self
                .result
                .as_ref()
                .ok()
                .and_then(|report| report.peak_memory_bytes),
            ..pending.clone()
        };
        let report = match &self.result {
            Ok(report) => report,
            Err(failure) => {
                return TypeDiagnostics::Failed {
                    check,
                    failure: failure.code().to_owned(),
                    measures: measure(&[]),
                    diagnostics: DiagnosticCollection::Inline {
                        diagnostics: Vec::new(),
                    },
                };
            }
        };
        let diagnostics: Vec<TypeDiagnostic> =
            report.diagnostics.iter().map(TypeDiagnostic::of).collect();
        let measures = measure(&diagnostics);
        let diagnostics = DiagnosticCollection::Inline { diagnostics };
        match report.incomplete {
            None => TypeDiagnostics::Complete {
                check,
                measures,
                diagnostics,
            },
            Some(failure) => TypeDiagnostics::Failed {
                check,
                failure: failure.code().to_owned(),
                measures,
                diagnostics,
            },
        }
    }
}

/// `diagnostics` with a collection past one reply kept whole in a body of
/// the run, its stored program's marks taken: the body, when one was kept.
/// A body that cannot be kept leaves the collection inline, traced.
fn keep_collection(
    storage: &ExecutorStorage<'_>,
    key: StepKey,
    source: Option<&CodeRunRawOutput>,
    diagnostics: TypeDiagnostics,
) -> (TypeDiagnostics, Option<CodeRunRawOutput>) {
    let past_one_reply = match &diagnostics {
        TypeDiagnostics::Complete {
            measures,
            diagnostics: DiagnosticCollection::Inline { diagnostics: list },
            ..
        }
        | TypeDiagnostics::Failed {
            measures,
            diagnostics: DiagnosticCollection::Inline { diagnostics: list },
            ..
        } if measures.bytes > RESULT_REPLY_INLINE_BYTES as u64 => Some(list.clone()),
        _ => None,
    };
    let Some(list) = past_one_reply else {
        return (diagnostics, None);
    };
    let (run, seq, invocation) = key;
    let kept = storage.code_run_output_sink().and_then(|mut sink| {
        write_json(&mut sink, &list)?;
        let path = type_diagnostics_output_path(seq, invocation);
        let body = storage.publish_code_run_output(path, sink, true, run)?;
        if let Some(source) = source {
            storage.inherit_code_run_result_marks(run, &body, &[(run, source.clone())])?;
        }
        Ok(body)
    });
    let body = match kept {
        Ok(body) => body,
        Err(error) => {
            tracing::warn!(target: "oneiron::code_check", %error, "type diagnostics body not kept");
            return (diagnostics, None);
        }
    };
    let stored = DiagnosticCollection::Stored {
        handle: body.handle.clone(),
        occurrence: crate::code_run::ResultOccurrence::of(Some(run), &body)
            .map(|occurrence| occurrence.id().to_hex())
            .unwrap_or_default(),
        byte_len: body.raw_len,
    };
    let diagnostics = match diagnostics {
        TypeDiagnostics::Complete {
            check, measures, ..
        } => TypeDiagnostics::Complete {
            check,
            measures,
            diagnostics: stored,
        },
        TypeDiagnostics::Failed {
            check,
            failure,
            measures,
            ..
        } => TypeDiagnostics::Failed {
            check,
            failure,
            measures,
            diagnostics: stored,
        },
        other => other,
    };
    (diagnostics, Some(body))
}

/// A landed check.
struct Landed {
    diagnostics: TypeDiagnostics,
    body: Option<CodeRunRawOutput>,
    /// Whether a collection past one reply is kept in its body already.
    finalized: bool,
    /// The checker and its answer, counted once the step's end is known.
    observed: Option<(Arc<FeedbackCheck>, Checked)>,
}

impl Landed {
    fn settled(diagnostics: TypeDiagnostics) -> Self {
        Self {
            diagnostics,
            body: None,
            finalized: true,
            observed: None,
        }
    }
}

/// One step's check as it stands, shared by its step and its check's
/// thread. Neither ever waits on the other.
pub(super) struct StepCell {
    key: StepKey,
    note: Option<ProgramPreparationNote>,
    actor: Option<EntityId>,
    source: Option<CodeRunRawOutput>,
    facts: TypeCheckFacts,
    state: Mutex<CellState>,
}

#[derive(Default)]
struct CellState {
    landed: Option<Landed>,
    then: Option<StepThen>,
    /// The step wrote its row pending: the check writes its own result.
    pending_kept: bool,
    /// A landed row is written, or being written.
    kept: bool,
}

impl StepCell {
    fn new(job: &CheckJob, facts: TypeCheckFacts) -> Self {
        Self {
            key: job.key,
            note: job.note.clone(),
            actor: job.actor,
            source: job.source.clone(),
            facts,
            state: Mutex::default(),
        }
    }

    pub(super) fn key(&self) -> StepKey {
        self.key
    }

    fn facts(&self) -> &TypeCheckFacts {
        &self.facts
    }

    /// The step's feedback as it stands now.
    pub(super) fn feedback(&self) -> ProgramStepFeedback {
        let diagnostics = lock(&self.state).landed.as_ref().map_or_else(
            || TypeDiagnostics::Pending {
                check: self.facts.clone(),
            },
            |landed| landed.diagnostics.clone(),
        );
        let (run, seq, invocation) = self.key;
        let step = ProgramStepIdentity::of(run, seq, invocation);
        ProgramStepFeedback::new(step, self.note.clone(), diagnostics)
    }

    /// Lands the check, and counts it once the step's end is known. With
    /// `writes`, the check's own row write: when the step wrote its row
    /// pending and no landed row is written yet.
    fn land(&self, landed: Landed, writes: bool) -> Option<StoredStepFeedback> {
        let mut state = lock(&self.state);
        state.landed = Some(landed);
        observe(&mut state, self.key);
        let owed = writes && state.pending_kept && !state.kept;
        if !owed {
            return None;
        }
        state.kept = true;
        drop(state);
        Some(self.row())
    }

    /// The row the step writes as it ends, or on a later turn: a landed
    /// check once, or a pending one once. `None` when its row is written.
    pub(super) fn claim_row(&self) -> Option<StoredStepFeedback> {
        let mut state = lock(&self.state);
        if state.landed.is_some() {
            if state.kept {
                return None;
            }
            state.kept = true;
        } else {
            if state.pending_kept {
                return None;
            }
            state.pending_kept = true;
        }
        drop(state);
        Some(self.row())
    }

    fn row(&self) -> StoredStepFeedback {
        let body = lock(&self.state)
            .landed
            .as_ref()
            .and_then(|landed| landed.body.clone());
        StoredStepFeedback::of(self.actor, &self.feedback(), body)
    }

    /// Keeps a landed collection past one reply in a body on `storage`, the
    /// run's own route, when its check could not and no landed row of it is
    /// written yet: a row written already keeps the collection where it is.
    pub(super) fn finalize(&self, storage: &ExecutorStorage<'_>) {
        let diagnostics = {
            let state = lock(&self.state);
            match &state.landed {
                Some(landed) if !landed.finalized && !state.kept => landed.diagnostics.clone(),
                _ => return,
            }
        };
        let (diagnostics, body) =
            keep_collection(storage, self.key, self.source.as_ref(), diagnostics);
        if let Some(landed) = lock(&self.state).landed.as_mut() {
            landed.diagnostics = diagnostics;
            landed.body = body;
            landed.finalized = true;
        }
    }

    /// How the step ended, for the counts.
    fn ended(&self, then: StepThen) {
        let mut state = lock(&self.state);
        if state.then.is_none() {
            state.then = Some(then);
            observe(&mut state, self.key);
        }
    }
}

/// Counts and traces a landed check once its step's end is known.
fn observe(state: &mut CellState, key: StepKey) {
    let Some(then) = state.then else {
        return;
    };
    let Some((checker, checked)) = state
        .landed
        .as_mut()
        .and_then(|landed| landed.observed.take())
    else {
        return;
    };
    let totals = checker
        .metrics()
        .observe(&checked.result, checked.elapsed, then);
    let (backend, codes, failure) = match &checked.result {
        Ok(report) => (
            report.backend.name,
            report
                .diagnostics
                .iter()
                .map(|diagnostic| diagnostic.code.to_string())
                .collect::<Vec<_>>()
                .join(","),
            report.incomplete.map_or("", CheckFailure::code),
        ),
        Err(failure) => (checked.backend.name, String::new(), failure.code()),
    };
    let (run, step, _) = key;
    tracing::info!(
        target: "oneiron::code_check",
        run_id = %run.to_hex(),
        step,
        backend,
        elapsed_us = u64::try_from(checked.elapsed.as_micros()).unwrap_or(u64::MAX),
        codes = %codes,
        failure,
        then = then.as_str(),
        checked = totals.checked,
        with_diagnostics = totals.with_diagnostics,
        diagnostic_occurrences = totals.diagnostic_occurrences,
        diagnostic_bytes = totals.diagnostic_bytes,
        then_with_diagnostics = ?totals.then_with_diagnostics,
        then_clean = ?totals.then_clean,
        codes_seen = ?totals.codes,
        unchecked = ?totals.unchecked,
        latency = ?totals.latency.get(backend),
        "code-mode program checked in feedback mode"
    );
}

/// One step's check, held by the step: dropping it counts the step as
/// failed unless [`Self::ended`] said otherwise. It never waits.
pub(super) struct StepCheck {
    cell: Arc<StepCell>,
    ended: bool,
}

impl StepCheck {
    fn of(cell: Arc<StepCell>) -> Self {
        Self { cell, ended: false }
    }

    /// A step no checker serves: its feedback is `diagnostics` from the
    /// start.
    pub(super) fn unavailable(job: &CheckJob, diagnostics: TypeDiagnostics) -> Self {
        let facts = TypeCheckFacts {
            language: job.language.as_str().to_owned(),
            file: job.language.file().to_owned(),
            backend: String::new(),
            pin: String::new(),
            action_digest: None,
            elapsed_us: None,
            peak_memory_bytes: None,
        };
        let cell = Arc::new(StepCell::new(job, facts));
        cell.land(Landed::settled(diagnostics), false);
        Self::of(cell)
    }

    pub(super) fn cell(&self) -> Arc<StepCell> {
        Arc::clone(&self.cell)
    }

    /// How the step ended: the run's status when it stopped there, or none
    /// when another step follows.
    pub(super) fn ended(&mut self, status: Option<&EngineExecutorStatus>) {
        self.ended = true;
        self.cell.ended(match status {
            Some(EngineExecutorStatus::Complete) => StepThen::Completed,
            Some(EngineExecutorStatus::Waiting(_)) => StepThen::Waiting,
            _ => StepThen::Continued,
        });
    }
}

impl Drop for StepCheck {
    fn drop(&mut self) {
        if !self.ended {
            self.cell.ended(StepThen::Failed);
        }
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}
