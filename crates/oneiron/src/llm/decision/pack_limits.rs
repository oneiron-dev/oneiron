//! Advisory observation of the policy's logical question-pack boundary.

use crate::Vault;
use crate::limit_ask::EngineLimit;

use super::DecisionBandPolicy;

impl Vault {
    /// Measures one logical pack against the same policy that groups its reads.
    /// Crossing asks through this vault's installed port; every question is served.
    pub fn measure_decision_pack(
        &self,
        policy: &DecisionBandPolicy,
        questions: usize,
    ) -> Option<u64> {
        self.measure_limit_at(
            EngineLimit::DecisionQuestionsPerCall,
            policy.questions_per_call() as u64,
            questions as u64,
        )
    }
}
