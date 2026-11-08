//! The Big rung's binding (OF-495): the big model on the seat
//! `[models.decisions.big]` names, and the provider a ladder's Big slot
//! holds over it. The host binds its own Big rung here
//! ([`DecisionHost`](super::DecisionHost)), and so does a caller that builds
//! its own ladder from the same models file (the route-calibration bench),
//! so both bind the rung one way.
//! Entry: BigRung::bind.

use std::sync::Arc;

use oneiron::Vault;
use oneiron::llm::decision::{
    DecisionProvider, DecisionQuestion, ModelDecisionProvider, ProviderPin,
};

use crate::big_rung::BigModel;
use crate::config::models::BigSettings;
use crate::models::ModelRuntime;

/// The Big rung `[models.decisions.big]` binds: the big model, and the
/// ladder provider over it.
pub struct BigRung {
    pub(super) model: Arc<BigModel>,
    pub(super) provider: Arc<dyn DecisionProvider>,
}

impl BigRung {
    /// The big model on `models`' seat for `settings`' role, reading
    /// `paired` jointly where its route reports token scores (FIX 1557).
    /// Each call is routed and admitted against `vault`'s live model policy,
    /// spends on the rung's own meter (`settings.budget_units`, else
    /// `default_units`) and blocks on `runtime`. Fails when no rung serves
    /// the seat.
    pub fn bind(
        settings: &BigSettings,
        models: &Arc<ModelRuntime>,
        vault: &Arc<Vault>,
        default_units: u64,
        runtime: tokio::runtime::Handle,
        paired: Option<DecisionQuestion>,
    ) -> anyhow::Result<Self> {
        let model = BigModel::bind(
            settings,
            Arc::clone(models),
            Arc::clone(vault),
            default_units,
            runtime,
        )?
        .with_paired(paired);
        let model = Arc::new(model);
        let provider = ModelDecisionProvider::new(model.pin(), Arc::clone(&model) as _)?;
        Ok(Self {
            model,
            provider: Arc::new(provider),
        })
    }

    /// The pin every answer of this rung carries.
    #[must_use]
    pub fn pin(&self) -> ProviderPin {
        self.model.pin()
    }

    /// The provider for a ladder's Big slot.
    #[must_use]
    pub fn provider(&self) -> &dyn DecisionProvider {
        self.provider.as_ref()
    }
}
