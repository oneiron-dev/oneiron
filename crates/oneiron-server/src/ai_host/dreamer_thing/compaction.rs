//! Compaction calls on the thing child's original generation count.

use std::sync::Arc;

use oneiron::code_run::{ScopedChildGeneration, ScopedChildGenerationCall, ScopedChildStop};
use oneiron::llm::WorkContext;
use oneiron::llm::manifest::ModelRole;

use super::generation::GenerationCount;
use crate::ai_host::DREAMER_EXTRACTION_ROLE;

pub(super) struct Generation {
    count: Arc<GenerationCount>,
    stop: ScopedChildStop,
    context: WorkContext,
}

impl Generation {
    pub(super) fn new(
        count: Arc<GenerationCount>,
        stop: ScopedChildStop,
        context: WorkContext,
    ) -> Self {
        Self {
            count,
            stop,
            context,
        }
    }
}

impl ScopedChildGeneration for Generation {
    fn admit(&self) -> Option<Box<dyn ScopedChildGenerationCall>> {
        if self.stop.code().is_some() || !self.count.admit() {
            return None;
        }
        Some(Box::new(Call(Some(Arc::clone(&self.count)))))
    }

    fn work_context(&self) -> WorkContext {
        self.context.clone()
    }

    fn live_role(&self) -> ModelRole {
        DREAMER_EXTRACTION_ROLE
    }
}

struct Call(Option<Arc<GenerationCount>>);

impl ScopedChildGenerationCall for Call {
    fn settle(mut self: Box<Self>, units: u64) {
        if let Some(count) = self.0.take() {
            count.settle(units);
        }
    }
}

impl Drop for Call {
    fn drop(&mut self) {
        if let Some(count) = self.0.take() {
            count.settle(0);
        }
    }
}
