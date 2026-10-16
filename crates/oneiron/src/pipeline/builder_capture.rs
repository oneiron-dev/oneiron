//! Retrieval telemetry capture and turn context options on the pipeline builder.

use super::PipelineBuilder;
use crate::context_pack::ContextPackRetrievalBudget;
use crate::store::RetrievalAction;

impl PipelineBuilder<'_> {
    pub(crate) fn telemetry_action(mut self, action: RetrievalAction) -> Self {
        self.telemetry_action = action;
        self
    }

    pub(crate) fn skill_executor_id(&self) -> Option<&str> {
        self.skill_executor.as_deref()
    }

    pub(crate) fn skill_reliability_query(
        &self,
    ) -> Option<&crate::skill_reliability::SkillReliabilityQuery> {
        self.skill_reliability_query.as_ref()
    }

    pub(crate) fn captures_replay(&self) -> bool {
        self.capture_retrieval_trace && self.vault.store.retrieval_telemetry_capture_enabled()
    }

    pub(crate) fn context_pack_budget(mut self, budget: ContextPackRetrievalBudget) -> Self {
        self.context_pack_budget = Some(budget);
        self
    }

    /// Selects an `All`-world pack's rows so non-base claims stay at most
    /// `floor(fraction × emitted claims)`, before the per-kind and result cuts.
    pub(crate) fn context_pack_world_share(mut self, fraction: f32) -> Self {
        self.context_pack_world_share = Some(fraction);
        self
    }

    /// Drops the rows a pack's disclosure clamp withholds before selection,
    /// listing them in `PipelineOutput::disclosure_clamped`.
    pub(crate) fn disclosure_preselect(
        mut self,
        clamp: crate::disclosure::DisclosureContext,
    ) -> Self {
        self.disclosure_preselect = Some(clamp);
        self
    }

    /// Retrieves a context pack's memory lane alone, without the skill and
    /// agent discovery that runs beside it.
    pub(crate) fn memory_lane_only(mut self) -> Self {
        self.capability_lanes = false;
        self
    }

    /// Enables opt-in per-stage retrieval trace capture for this run.
    /// Supplies the pre-decision bus for iterative or offline replay callers.
    pub fn retrieval_state(mut self, state: crate::store::RetrievalState) -> Self {
        self.retrieval_state = Some(state);
        self
    }
    /// Enables the bounded OF-092 policy for this run. Set `bandit_enabled`
    /// false for deterministic replay. Learned tiers never change read authority.
    pub fn retrieval_policy(
        mut self,
        options: crate::pipeline::retrieval_policy::RetrievalPolicyOptions,
    ) -> Self {
        self.retrieval_policy = Some(options);
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

    /// Names a host-owned, access-controlled query packet or session message.
    /// It must contain any generated queries and vectors needed for exact replay.
    /// The telemetry row stores this reference, never the query or its hash.
    pub fn replay_query_ref(mut self, query_ref: impl Into<String>) -> Self {
        self.replay_query_ref = Some(query_ref.into());
        self
    }

    pub fn capture_retrieval_trace(mut self, enabled: bool) -> Self {
        self.capture_retrieval_trace = enabled;
        self
    }
}
