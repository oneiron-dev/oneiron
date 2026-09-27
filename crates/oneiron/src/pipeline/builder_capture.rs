//! Retrieval telemetry capture and turn context options on the pipeline builder.

use super::PipelineBuilder;
use crate::context_pack::ContextPackRetrievalBudget;
use crate::store::RetrievalAction;

impl PipelineBuilder<'_> {
    pub(crate) fn telemetry_action(mut self, action: RetrievalAction) -> Self {
        self.telemetry_action = action;
        self
    }

    pub(crate) fn captures_replay(&self) -> bool {
        self.capture_retrieval_trace
    }

    pub(crate) fn context_pack_budget(mut self, budget: ContextPackRetrievalBudget) -> Self {
        self.context_pack_budget = Some(budget);
        self
    }

    /// Enables opt-in per-stage retrieval trace capture for this run.
    /// Supplies the pre-decision bus for iterative or offline replay callers.
    pub fn retrieval_state(mut self, state: crate::store::RetrievalState) -> Self {
        self.retrieval_state = Some(state);
        self
    }
    pub fn retrieval_turn(mut self, turn: crate::store::RetrievalTurn) -> Self {
        self.retrieval_turn = Some(turn);
        self
    }

    /// Binds opt-in replay telemetry to an immutable host-owned corpus snapshot.
    /// The reference is persisted, not used to change retrieval.
    pub fn corpus_snapshot_ref(mut self, snapshot_ref: impl Into<String>) -> Self {
        self.corpus_snapshot_ref = Some(snapshot_ref.into());
        self
    }

    pub fn capture_retrieval_trace(mut self, enabled: bool) -> Self {
        self.capture_retrieval_trace = enabled;
        self
    }
}
