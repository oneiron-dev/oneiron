//! Core half of `store::retrieval_deadline`: its store-layer items live in `oneiron_store::retrieval_deadline` and are
//! re-exported here; the items below stay in the engine.

pub use oneiron_store::retrieval_deadline::*;

use crate::error::{Error, Result};
use crate::store::RetrievalSignal;
use oneiron_model::llm::WorkCancel;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::time::{Duration, Instant};

#[cfg(any(test, feature = "test-hooks"))]
impl crate::Vault {
    /// Arms (or, with `None`, disarms) this vault's slow retrieval stage.
    #[doc(hidden)]
    pub fn arm_slow_retrieval_stage_for_test(&self, stage: Option<SlowRetrievalStage>) {
        *self
            .slow_retrieval_stage
            .lock()
            .expect("slow retrieval stage hook") = stage;
    }

    pub(crate) fn run_slow_retrieval_stage(
        &self,
        signal: crate::store::RetrievalSignal,
        deadline: &RetrievalDeadline,
    ) -> Result<()> {
        let armed = *self
            .slow_retrieval_stage
            .lock()
            .expect("slow retrieval stage hook");
        let Some(slow) = armed.filter(|slow| slow.signal == signal) else {
            return Ok(());
        };
        let until = deadline.now() + slow.duration;
        loop {
            let left = until.saturating_duration_since(deadline.now());
            if left.is_zero() {
                return Ok(());
            }
            if slow.yields {
                deadline.checkpoint()?;
            }
            deadline.spend(left.min(Duration::from_millis(1)));
        }
    }
}
