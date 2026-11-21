//! Door for `tests/dreamer_route_fences_withdrawn_source_rows.rs`
//! ([DREAMER-STEP-RESENDS-ERASED-SOURCE-WORDS]): a Dreamer role's route as
//! a pass lends it to the engine, which binds each call to the rows its
//! input was read from, over one seat of a runtime whose rests are kept in
//! the test's vault, as a served vault's are.
use std::sync::Arc;

use oneiron::dreamer_consolidation::SourcedBackend;
use oneiron::llm::manifest::ModelRole;
use oneiron::llm::run_admission::RunAdmission;
use oneiron::{EntityId, LlmBackend, ModelId, Vault};

use super::request_sources::SourcedRunBackend;
use crate::config::models::ModelsConfig;
use crate::models::{ModelRuntime, OfferCooldowns};

/// One Dreamer role's route, as a pass lends it: its seat's model, and the
/// route each call of the role sends on bound to its rows.
pub struct LentDreamerRoute {
    model: ModelId,
    route: SourcedRunBackend,
    /// The runtime the seat's ladder is of, kept as long as the route.
    _runtime: ModelRuntime,
}

impl LentDreamerRoute {
    /// The model the seat's first rung serves.
    #[must_use]
    pub fn model(&self) -> &ModelId {
        &self.model
    }

    /// The route for one call whose input was read from `rows`, as the
    /// engine's [`SourcedBackend`] borrows it.
    #[must_use]
    pub fn sourced(&self, rows: Vec<EntityId>) -> Box<dyn LlmBackend + '_> {
        SourcedBackend::sourced(&self.route, rows)
    }
}

/// `role`'s seat of `models`, its rests kept in `vault`, lent under `run` as
/// a pass lends a role's route. `None` when no seat serves `role`.
#[must_use]
pub fn lent_dreamer_route(
    models: &ModelsConfig,
    vault: &Arc<Vault>,
    role: ModelRole,
    run: RunAdmission,
) -> Option<LentDreamerRoute> {
    let runtime = ModelRuntime::build_hosted(
        Some(models),
        None,
        OfferCooldowns::in_vault(Arc::clone(vault)),
        oneiron::HostingPrivacyPosture::SelfHostLocal,
    );
    let seat = runtime.seat(role)?;
    let model = seat.model.clone();
    let route = SourcedRunBackend::new(Arc::clone(&seat.ladder), run);
    Some(LentDreamerRoute {
        model,
        route,
        _runtime: runtime,
    })
}
