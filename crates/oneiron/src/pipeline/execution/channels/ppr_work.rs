//! One fair task-work admission for PPR's snapshot.

use std::sync::Arc;

use crate::error::{Error, Result};
use crate::pipeline::builder::PipelineBuilder;
use crate::work_line::TaskWorkTurn;

impl PipelineBuilder<'_> {
    pub(super) fn admit_ppr_work(&self) -> Result<Option<Arc<TaskWorkTurn>>> {
        let required = self.ppr_expand.is_some()
            || self.ppr_search.as_ref().is_some_and(|(seeds, depth)| {
                seeds.len() > crate::ppr::MAX_PPR_SEEDS || *depth > crate::ppr::MAX_PPR_DEPTH
            });
        if !required {
            return Ok(None);
        }
        // A host that already holds the turn carries it through; admission
        // never nests behind the same operation's own permit.
        if let Some(turn) = &self.ppr_work {
            return Ok(Some(turn.clone()));
        }
        let caller = self
            .execution_actor
            .map(|actor| actor.entity_ref())
            .or_else(|| {
                self.scoped_note_reader
                    .as_ref()
                    .and_then(|reader| reader.authenticated_person())
            });
        // Canonical native PPR has no work context and keeps today's immediate
        // path. An actor-bound request waits fairly or reaches its own deadline.
        let Some(caller) = caller else {
            return Ok(None);
        };
        let turn = match self.deadline {
            Some(deadline) => self
                .vault
                .admit_task_work_blocking_until(caller, deadline.answer_at())
                .map_err(|_| Error::RetrievalStageCut)?,
            None => self.vault.admit_task_work_blocking(caller),
        };
        Ok(Some(Arc::new(turn)))
    }
}
