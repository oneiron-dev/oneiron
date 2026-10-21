//! Decision host attach: the server's decision ladder and its config.
//! Entry: SyncServer.
//! Definitions: types stay in the parent; this module owns the listed impls.

use super::{DecisionHost, HeldLadder, ModelId, ModelsConfig, SeatDecisions, SyncServer};

impl SyncServer {
    /// Sets the vault's credential-broker context, which serve builds once
    /// after the vault opens: the System One seat `[models.decisions]` binds
    /// at the model attach sends through it when its key is a `key_secret`.
    #[must_use]
    pub(crate) fn with_broker(mut self, broker: Option<crate::models::BrokerContext>) -> Self {
        self.decisions.broker = broker;
        self
    }

    /// The vault's credential-broker context serve set, which the model
    /// attach's `key_secret` providers send through too.
    pub(crate) fn broker_context(&self) -> Option<&crate::models::BrokerContext> {
        self.decisions.broker.as_ref()
    }

    /// The host's decision ladder, built once at serve start. Every typed
    /// decision a route or runtime job asks goes through it
    /// (`decision_ladder().ladder()` for one call).
    #[must_use]
    pub fn decision_ladder(&self) -> &HeldLadder {
        self.decisions.ladder()
    }

    /// The ladder with its owner ask queue, starting bands, dials and the
    /// hooks built on it.
    #[must_use]
    pub fn decision_host(&self) -> &DecisionHost {
        &self.decisions
    }

    /// [`DecisionHost::ladder_for_model`] on this server's ladder.
    pub fn decision_ladder_for_model(&self, model: &ModelId) -> anyhow::Result<HeldLadder> {
        self.decisions.ladder_for_model(model)
    }

    /// [`DecisionHost::ladder_for_role`] on this server's ladder.
    pub fn decision_ladder_for_role(
        &self,
        role: oneiron::llm::manifest::ModelRole,
    ) -> anyhow::Result<HeldLadder> {
        self.decisions.ladder_for_role(role)
    }

    /// The family `model` belongs to, as its provider's config or its
    /// registry row names it; a seat's when every rung shares one. `None`
    /// when nothing names it, never guessed.
    pub fn model_family(&self, model: &ModelId) -> oneiron::Result<Option<String>> {
        self.ai.models().model_family(&self.vault, model)
    }

    /// Every chat model served alone by its own id whose known family is
    /// none of `models`', in id order: where a third opinion may come from,
    /// each one a [`Self::decision_ladder_for_model`] takes. Empty when any
    /// of `models` has no known family.
    pub fn models_outside_families(&self, models: &[&ModelId]) -> oneiron::Result<Vec<ModelId>> {
        self.ai
            .models()
            .models_outside_families(&self.vault, models)
    }

    /// Fills the ladder's rungs `[models]` binds beyond the house read, and
    /// builds the hooks `[models.decisions]` words.
    pub(crate) fn with_decision_config(mut self, models: Option<&ModelsConfig>) -> Self {
        let Some(models) = models else {
            return self;
        };
        let principal = match self.vault.ensure_embedded_owner_actor() {
            Ok(owner) => Some(owner),
            Err(error) => {
                tracing::warn!(%error, "no owner principal; the host's own decisions stay unbound");
                None
            }
        };
        let posture = self.vault.privacy_posture();
        self.decisions = self
            .decisions
            .clone()
            .with_system_one(
                models.decisions.system_one.as_ref(),
                models.raw_budget_units,
                posture,
                tokio::runtime::Handle::current(),
            )
            .with_local_vision(
                &self.ai,
                &self.vault,
                models.raw_budget_units,
                tokio::runtime::Handle::current(),
            )
            .with_big(
                models.decisions.big.as_ref(),
                self.ai.models(),
                &self.vault,
                models.raw_budget_units,
                tokio::runtime::Handle::current(),
            )
            .with_auto_check(models.decisions.auto_check.as_deref(), principal)
            .with_image_pick(models.decisions.image_pick.as_ref())
            .with_booking_parse(models.decisions.booking_parse.clone())
            .with_connector_slate(models.decisions.connector_slate.as_ref())
            .with_import_audience(models.decisions.import_audience.as_ref())
            .with_wire_health(models.decisions.wire_health.as_deref());
        self
    }

    /// The code-mode seat pick `[models.decisions.seat]` words, and its facet.
    pub(crate) fn seat_router(&self, models: &ModelsConfig) -> Option<(SeatDecisions, String)> {
        let settings = models.decisions.seat.as_ref()?;
        let principal = self
            .vault
            .ensure_embedded_owner_actor()
            .inspect_err(|error| {
                tracing::warn!(%error, "no owner principal; the seat pick stays unbound");
            })
            .ok()?;
        Some((
            self.decisions.seat_decisions(settings, principal),
            settings.facet.clone(),
        ))
    }
}
