//! A compaction seat on a host-profiled child's original generation.

use std::sync::Arc;

use oneiron::code_run::{CompactionHostBinding, ScopedChildProfile};
use oneiron::engine_executor::RunCompaction;
use oneiron::llm::manifest::ModelRole;
use oneiron::{LlmRequest, Vault};

use super::{CodeModeCompaction, CompactionMeter, LiveAdmission};
use crate::models::{ModelRuntime, RoleCall, RoleRefusal};

#[cfg(feature = "code-sandbox-wasmtime")]
pub(super) fn seat(
    compaction: &CodeModeCompaction,
    host: CompactionHostBinding,
    credential: &str,
    profile: &ScopedChildProfile,
) -> Option<RunCompaction> {
    let generation = profile.generation.as_ref()?;
    let live = match compaction {
        CodeModeCompaction::Off(why) => return Some(RunCompaction::off(*why)),
        CodeModeCompaction::Live(live) => live,
    };
    let house = live.served.first()?;
    let admission: Arc<dyn LiveAdmission> = Arc::new(Live {
        vault: Arc::clone(&house.vault),
        models: Arc::clone(&house.models),
        role: generation.live_role(),
    });
    Some(compaction.for_meter(
        host,
        credential,
        Some(CompactionMeter::Profiled {
            guard: profile.guard.clone(),
            generation: Arc::clone(generation),
        }),
        &admission,
    ))
}

struct Live {
    vault: Arc<Vault>,
    models: Arc<ModelRuntime>,
    role: ModelRole,
}

impl LiveAdmission for Live {
    fn admit_live(&self, request: LlmRequest) -> Result<RoleCall, RoleRefusal> {
        self.models
            .admit_seat_bound(&self.vault, self.role, request)
    }
}
