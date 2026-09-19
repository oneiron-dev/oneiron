//! Generation-owned budget reservation. All stop/drop paths release it exactly once.
use std::sync::Arc;
use crate::llm::{BudgetGuard, BudgetLease, LlmUsage};

pub(super) struct GenerationBudget {
    pub(super) guard: Arc<BudgetGuard>,
    pub(super) lease: BudgetLease,
    pub(super) usage: LlmUsage,
}
impl Drop for GenerationBudget {
    fn drop(&mut self) {
        if self.usage.input.total == 0 && self.usage.output.total == 0 {
            let _ = self.guard.abort(&self.lease);
        } else {
            let _ = self.guard.settle_per_call(&self.lease, &self.usage);
        }
    }
}
