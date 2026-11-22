//! Door for `tests/thing_child_fences_lent_source_rows.rs`
//! ([DREAMER-UNSOURCED-ROLE-CALLS-SEND-UNFENCED]): a Dreamer thing child's
//! generation as its host builds it, over one seat of a runtime whose rests
//! are kept in the test's vault, as a served vault's are.
//! And the generation such a child lends its compaction, as its host
//! builds it at launch.
use std::sync::Arc;

use oneiron::attempt_queue::AttemptId;
use oneiron::code_run::{ScopedChildGeneration, ScopedChildStop};
use oneiron::llm::WorkContext;
use oneiron::llm::manifest::ModelRole;
use oneiron::llm::run_admission::RunAdmission;
use oneiron::{EntityId, LlmBackend, ModelId, Vault};

use crate::config::models::ModelsConfig;
use crate::models::{ModelRuntime, OfferCooldowns, RunBackend};

/// A thing child's generation, as its host lends it: the seat's model and
/// the backend each code step calls.
pub struct ThingChildRoute {
    model: ModelId,
    backend: RunBackend,
    /// The runtime the seat's ladder is of, kept as long as the route.
    _runtime: ModelRuntime,
}

impl ThingChildRoute {
    /// The model the seat's first rung serves.
    #[must_use]
    pub fn model(&self) -> &ModelId {
        &self.model
    }

    /// The backend a child's code step sends on.
    #[must_use]
    pub fn backend(&self) -> &dyn LlmBackend {
        &self.backend
    }
}

/// `role`'s seat of `models`, its rests kept in `vault`, as a thing child's
/// host builds the child's generation under `run` for a child lent slices
/// read from `lent`. `None` when no seat serves `role`.
#[must_use]
pub fn thing_child_route(
    models: &ModelsConfig,
    vault: &Arc<Vault>,
    role: ModelRole,
    run: RunAdmission,
    lent: Vec<EntityId>,
) -> Option<ThingChildRoute> {
    let runtime = ModelRuntime::build_hosted(
        Some(models),
        None,
        OfferCooldowns::in_vault(Arc::clone(vault)),
        oneiron::HostingPrivacyPosture::SelfHostLocal,
    );
    let seat = runtime.seat(role)?;
    let model = seat.model.clone();
    let backend =
        super::child_generation_backend(Arc::clone(&seat.ladder), run, Arc::clone(vault), lent);
    Some(ThingChildRoute {
        model,
        backend,
        _runtime: runtime,
    })
}

/// The generation a thing child lent slices read from `lent` lends its
/// compaction, as its host builds it at launch: on a generation count of
/// its own attempt line, under no stop, in a default work context.
#[must_use]
pub fn thing_child_generation(
    vault: &Arc<Vault>,
    lent: Vec<EntityId>,
) -> Arc<dyn ScopedChildGeneration> {
    let count = Arc::new(super::generation::GenerationCount::new(
        Arc::clone(vault),
        "thing-child-generation".to_owned(),
        AttemptId::now(),
        EntityId::now(),
    ));
    Arc::new(super::compaction::Generation::new(
        count,
        ScopedChildStop::default(),
        WorkContext::default(),
        lent,
    ))
}
