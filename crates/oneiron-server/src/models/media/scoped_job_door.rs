//! Doors for `tests/media_job_staged_spend.rs`
//! ([MEDIA-JOB-SPEND-LOST-ON-PROCESS-DEATH], S7299-P1): a video job a spend
//! scope funds, kept as its submit leaves it, and its poll's end path, whole
//! or stopped before its drain.
use std::collections::BTreeMap;
use std::sync::Arc;

use oneiron::agent_dispatch::SpendScopeId;
use oneiron::llm::media::{AiOperation, MediaJobState, MediaRequest};
use oneiron::{
    BudgetGuard, CallClass, CallEnvelope, CallPurpose, FatalLlmError, LlmResult, ModelId,
    ModelLocality, ModelTierRef, ResponseFormat, TierPrecedence,
};

use super::jobs::JobRow;
use super::run_line::JobLine;
use super::{MediaRuntime, funded_run, replay};

/// The rung the kept job names: no rung of this runtime's serves it.
const DOOR_MODEL: &str = "door/video@1";

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
