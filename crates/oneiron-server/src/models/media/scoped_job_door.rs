//! Doors for `tests/media_job_staged_spend.rs`
//! ([MEDIA-JOB-SPEND-LOST-ON-PROCESS-DEATH], S7299-P1): a video job a spend
//! scope funds, kept as its submit leaves it, and its poll's end path, whole
//! or stopped before its drain; a job whose end the vault refused, held
//! here; and two ends of one job that meet after their snapshots of its
//! scope's part (S7299 review round 3 P1).
use std::collections::BTreeMap;
use std::sync::{Arc, Condvar, Mutex, PoisonError};
use std::time::Duration;

use oneiron::agent_dispatch::SpendScopeId;
use oneiron::llm::media::{AiOperation, MediaJobState, MediaRequest};
use oneiron::{
    BudgetGuard, CallClass, CallEnvelope, CallPurpose, FatalLlmError, LlmResult, ModelId,
    ModelLocality, ModelTierRef, ResponseFormat, TierPrecedence,
};

use super::jobs::JobRow;
use super::run_line::JobLine;
use super::{Held, MediaRuntime, funded_run, replay};

/// The rung the kept job names: no rung of this runtime's serves it.
const DOOR_MODEL: &str = "door/video@1";

/// How long an end whose snapshot meets waits for the other end's.
const END_MEET_WAIT: Duration = Duration::from_secs(5);

/// The jobs whose ends meet after their snapshots, by ticket
/// ([`MediaRuntime::meet_end_snapshots_for_test`]).
static END_MEETS: Mutex<BTreeMap<String, Arc<EndMeet>>> = Mutex::new(BTreeMap::new());

/// Two ends of one job, met after their snapshots of its scope's part: how
/// many took theirs.
#[derive(Default)]
struct EndMeet {
    taken: Mutex<usize>,
    second: Condvar,
}

/// Called by each end of job `ticket` once it took its snapshot of the part
/// of its scope's that it stages (`write_kept_end`). An end of a job that
/// [`MediaRuntime::meet_end_snapshots_for_test`] named waits there until a
/// second end of the job took its snapshot too, or [`END_MEET_WAIT`]
/// passes: where nothing serializes the two ends, both snapshot before
/// either commits. Every other end passes straight through.
pub(super) fn end_snapshot_taken(ticket: &str) {
    let meet = END_MEETS
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .get(ticket)
        .cloned();
    let Some(meet) = meet else {
        return;
    };
    let mut taken = meet.taken.lock().unwrap_or_else(PoisonError::into_inner);
    *taken = taken.saturating_add(1);
    meet.second.notify_all();
    drop(
        meet.second
            .wait_timeout_while(taken, END_MEET_WAIT, |taken| *taken < 2)
            .unwrap_or_else(PoisonError::into_inner),
    );
}

impl MediaRuntime {
    /// Keeps a video job `scope` funds as `submit_scoped` leaves it once its
    /// provider answered, and answers its ticket: its run under `run`'s name
    /// on `guard`, a guard of the scope's own, held for its end's booking
    /// with what that guard used so far booked on the scope
    /// (`hold_scoped`), and its running row kept with the scope on its line.
    pub(crate) fn keep_scoped_job_for_test(
        &self,
        run: &str,
        scope: SpendScopeId,
        guard: BudgetGuard,
    ) -> LlmResult<String> {
        let ticket = replay::fresh_ticket();
        let admitted = funded_run(
            run.to_owned(),
            guard,
            self.host.clone(),
            Arc::clone(&self.receipts),
            None,
        );
        self.hold_scoped(&ticket, scope.clone(), admitted);
        let row = JobRow {
            model: door_model()?,
            operation: AiOperation::Video,
            provider_job: Some(format!("provider-{ticket}")),
            request: door_request()?,
            ended: None,
            receipt: None,
            payer: None,
            stamps: Default::default(),
            erased: false,
            replay_until_s: None,
            paid: false,
            line: Some(JobLine {
                run: run.to_owned(),
                scope: Some(scope),
            }),
        };
        let kept = self.scoped_store()?.put(&ticket, row).map_err(|message| {
            FatalLlmError::InvalidRequestDetail {
                message,
                code: None,
            }
        })?;
        if !kept {
            return Err(FatalLlmError::InvalidRequest.into());
        }
        Ok(ticket)
    }

    /// A poll's end of job `ticket` up to its drain: the commit that writes
    /// its end `state` and stages its scope's part, and no drain, as a
    /// process that dies there.
    pub(crate) fn write_kept_end_for_test(
        &self,
        ticket: &str,
        state: &MediaJobState,
    ) -> LlmResult<MediaJobState> {
        self.write_kept_end(ticket, state).0
    }

    /// A poll's whole end of job `ticket`: the commit that writes its end
    /// `state` and stages its scope's part, then the drain.
    pub(crate) fn complete_kept_job_for_test(
        &self,
        ticket: &str,
        state: &MediaJobState,
    ) -> LlmResult<MediaJobState> {
        self.complete_kept_job(ticket, state)
    }

    /// Holds job `ticket` here with its end `state`, as a poll leaves it
    /// whose end row and held end the vault both refused
    /// (`write_kept_end`): `Held::Unkept`, its row still running in the
    /// vault, and its scope's part in its ledger only.
    pub(crate) fn end_refused_for_test(&self, ticket: &str, state: &MediaJobState) {
        self.lock_jobs()
            .insert(ticket.to_owned(), Held::Unkept(state.clone()));
    }

    /// Makes the ends of job `ticket` meet after their snapshots of its
    /// scope's part ([`end_snapshot_taken`]).
    pub(crate) fn meet_end_snapshots_for_test(&self, ticket: &str) {
        END_MEETS
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(ticket.to_owned(), Arc::default());
    }
}

fn door_model() -> LlmResult<ModelId> {
    ModelId::new(DOOR_MODEL).map_err(|_| FatalLlmError::InvalidRequest.into())
}

/// A bare `ai.video` call on [`DOOR_MODEL`].
fn door_request() -> LlmResult<MediaRequest> {
    let purpose = CallPurpose::Other {
        name: format!("ai.{}", AiOperation::Video.as_str()),
    };
    Ok(MediaRequest {
        model: door_model()?,
        envelope: CallEnvelope {
            scope: Default::default(),
            tier: TierPrecedence::for_purpose(
                &purpose,
                ModelTierRef(format!("media-{}", AiOperation::Video.as_str())),
            ),
            purpose,
            class: CallClass::BestEffort,
            response_format: ResponseFormat::Text,
            locality: ModelLocality::OwnServer,
            host_keyless: false,
            host_paid: false,
            seat_effort: None,
        },
        operation: AiOperation::Video,
        parts: Vec::new(),
        references: Vec::new(),
        mask: None,
        params: BTreeMap::new(),
        voice: None,
    })
}
