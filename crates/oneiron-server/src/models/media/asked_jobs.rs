//! The video jobs an agent asked for under the owner's `ai.video` Grant
//! (FIX 3208). Its job bills the owner, as his own does, and its row is
//! stamped with the agent as the actor that asked (KS-2B2); the agent's poll
//! and cancel reach only such a job. A job whose row was not kept, or was
//! erased, is no job of the agent's.
//! Entry: `MediaRuntime::poll_asked_by`, `cancel_asked_by`.
use oneiron::EntityId;
use oneiron::llm::media::MediaJobState;

use super::{FatalLlmError, KeptJob, LlmResult, MediaRuntime};

impl MediaRuntime {
    /// Whether job `id`'s kept row was stamped at its submit with `actor` as
    /// the actor that asked.
    fn asked_by(&self, id: &str, actor: EntityId) -> bool {
        matches!(
            self.store.as_ref().and_then(|store| store.get(id)),
            Some(KeptJob::Row(row)) if !row.erased && row.stamps.actor == Some(actor)
        )
    }

    /// [`Self::poll`] for an agent the owner's `ai.video` Grant admits: a job
    /// it asked for. Any other job is no job of the agent's.
    pub(crate) async fn poll_asked_by(
        &self,
        actor: EntityId,
        id: &str,
    ) -> LlmResult<MediaJobState> {
        if !self.asked_by(id, actor) {
            return Err(FatalLlmError::InvalidRequest.into());
        }
        self.poll(id).await
    }

    /// [`Self::cancel`] for an agent the owner's `ai.video` Grant admits, as
    /// [`Self::poll_asked_by`] reaches a job.
    pub(crate) async fn cancel_asked_by(&self, actor: EntityId, id: &str) -> LlmResult<()> {
        if !self.asked_by(id, actor) {
            return Err(FatalLlmError::InvalidRequest.into());
        }
        self.cancel(id).await
    }
}
