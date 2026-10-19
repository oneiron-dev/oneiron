//! `tasks.wait({request, step_key})` (FIX 4706): a code run's wait on one
//! world-privacy request its actor opened, beside the reader-children wait
//! the same row takes. It needs no reader child, quorum or reader cutoff:
//! the request's id is the wait's, a pending request parks the run on it as
//! a human response, and the commit that applies or declines it delivers its
//! terminal state as the run's reply. A settled request answers at once.

use super::HostSelfDispatcher;
use crate::EntityId;
use crate::code_run::storage::ExecutorStorage;
use crate::code_run::types::{SelfDispatchOutcome, SelfEffect, SelfFailedResult};
use crate::code_run::{TaskWaitSetCall, valid_reader_key};
use crate::error::Result;
use crate::task_verb::{TaskAskStatus, TaskAskWait};

impl HostSelfDispatcher<'_> {
    /// The run's wait on world-privacy request `request`, as the run's own
    /// actor, the one that opened it: its terminal state, or the park on its
    /// id. A call that names children or a reader policy beside it, a bad
    /// id or step key, a run bound to a room, or any actor but the request's
    /// fails, and nothing waits.
    pub(super) fn dispatch_world_privacy_wait(
        &self,
        call: &TaskWaitSetCall,
        request: &str,
    ) -> Result<SelfDispatchOutcome> {
        let failed = |code: &str| {
            SelfDispatchOutcome::Failed(SelfFailedResult {
                effect: SelfEffect::TasksWaitSet,
                error: code.to_owned(),
            })
        };
        let alone = call.tasks.is_empty()
            && call.all.is_none()
            && call.n_of.is_none()
            && call.until.is_none();
        let Ok(request) = EntityId::from_hex(request) else {
            return Ok(failed("task_wait_invalid"));
        };
        if !alone || !valid_reader_key(&call.step_key) {
            return Ok(failed("task_wait_invalid"));
        }
        // A request is the canonical vault's; a run bound to a room waits on
        // none.
        let ExecutorStorage::Canonical(vault) = &self.storage else {
            return Ok(failed("task_wait_unbound"));
        };
        let memory = vault.memory(self.actor.entity_ref(), self.actor.actor_class());
        Ok(match memory.world_privacy_run_wait(request) {
            Ok(Some(TaskAskWait::Park(wait))) => SelfDispatchOutcome::DurableWait(wait),
            Ok(Some(TaskAskWait::WorldPrivacyReady(request))) => {
                SelfDispatchOutcome::TaskAskStatus(TaskAskStatus::WorldPrivacy(request))
            }
            Ok(Some(_) | None) => failed("task_wait_invalid"),
            Err(error) => failed(&error.code),
        })
    }
}
