//! Eval-mode inputs for replaying a fixed query pack (RESEARCH-0651 Tier 0).
//! The retrieval ruler compares blend weights in a fresh, throwaway pack vault;
//! each run pins its clock and weight source without persisting its results.

use super::PipelineBuilder;

/// The eval mode of one retrieval run (RESEARCH-0651 Tier 0, the retrieval ruler).
#[derive(Clone, Debug, PartialEq)]
pub struct RetrievalEvalSpec {
    /// The run's clock, in unix seconds. Every recency and age score reads it in place of the wall clock.
    pub now: u64,
    /// Where the run's blend weights come from.
    pub weights: BlendWeightsSource,
}

/// The blend weights of one eval run.
#[derive(Clone, Debug, PartialEq)]
pub enum BlendWeightsSource {
    /// The vault's own learned table (in a fresh pack vault: the shipped bootstrap weights).
    LearnedTable,
    /// These weights for this run alone (normalized, never written).
    Pinned(crate::store::RetrievalBlendWeights),
}

impl PipelineBuilder<'_> {
    /// Pins the clock and blend-weight source for one retrieval-ruler replay.
    /// A learned-table spec clears an earlier override; pinned weights are
    /// normalized and validated without changing the vault's learned table.
    /// Call it before `retrieval_effort`: that plan anchors its temporal search
    /// at the clock it finds when it is called.
    ///
    /// At run time, refuses nondeterministic rerankers, HyDE model calls,
    /// RNG-driven bandit policies, wall-clock deadlines and room sessions.
    /// Never writes a retrieval-run row, a PPR cache row or an embed job.
    pub fn eval_spec(mut self, spec: RetrievalEvalSpec) -> crate::Result<Self> {
        self.temporal_now = Some(spec.now);
        match spec.weights {
            BlendWeightsSource::LearnedTable => self.blend_weights_override = None,
            BlendWeightsSource::Pinned(weights) => self = self.with_blend_weights(weights)?,
        }
        self.eval = true;
        Ok(self)
    }

    pub(in crate::pipeline) fn refuse_nondeterminism(&self) -> crate::Result<()> {
        if self
            .rerank
            .as_ref()
            .is_some_and(|(reranker, _)| !reranker.deterministic())
        {
            return Err(crate::Error::InvalidConfig(
                "eval mode needs a deterministic reranker".into(),
            ));
        }
        if self.hyde.is_some() {
            return Err(crate::Error::InvalidConfig(
                "eval mode refuses a HyDE expander (a model call)".into(),
            ));
        }
        if self
            .retrieval_policy
            .as_ref()
            .is_some_and(|policy| policy.bandit_enabled)
        {
            return Err(crate::Error::InvalidConfig(
                "eval mode refuses the bandit (it draws from an RNG)".into(),
            ));
        }
        if self.deadline.is_some() {
            return Err(crate::Error::InvalidConfig(
                "eval mode refuses a deadline (wall-clock skips)".into(),
            ));
        }
        if self.session.is_some() {
            return Err(crate::Error::InvalidConfig(
                "eval mode runs outside any room session".into(),
            ));
        }
        Ok(())
    }
}
