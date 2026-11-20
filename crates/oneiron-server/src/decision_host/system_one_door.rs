//! Door for `tests/systemone_pack_run_no_cancel.rs` (SYSTEMONE-PACK-RUN-NO-CANCEL):
//! the System One rung bound to a stub endpoint, so a test can hold its seat
//! call pending and cancel the work under it. Thin wrapper over crate items
//! only. Compiled only under `--cfg oneiron_test_support`; hidden, never API.

use std::sync::Arc;

use oneiron::llm::decision::{DecisionCall, DecisionPack, DecisionProvider, ProviderDecision};
use oneiron::llm::run_admission::{KeyCustody, LeaseUnit, OfferRoute, PaidConnector, Payer};
use oneiron::{BudgetExhaustionPolicy, BudgetGuard, HostingPrivacyPosture, ModelLocality, Vault};

use super::SystemOneRung;

/// The System One rung against a stub seat, as `SystemOneRung::bind`
/// binds a `key_env` seat.
#[doc(hidden)]
pub struct SystemOneRungForTest {
    rung: SystemOneRung,
}

impl SystemOneRungForTest {
    /// [`DecisionProvider::decide`] on the stub-bound rung.
    #[doc(hidden)]
    pub fn decide(&self, call: &DecisionCall<'_>) -> oneiron::Result<ProviderDecision> {
        DecisionProvider::decide(&self.rung, call)
    }

    /// [`DecisionProvider::decide_pack`] on the stub-bound rung.
    #[doc(hidden)]
    pub fn decide_pack(&self, pack: &DecisionPack<'_>) -> oneiron::Result<Vec<ProviderDecision>> {
        DecisionProvider::decide_pack(&self.rung, pack)
    }
}

/// The System One rung against the stub seat at `endpoint`, holding `bearer`
/// from bind as a `key_env` seat does, so its key sits at T1. The rung's own
/// meter only serves calls without a caller's run.
///
/// # Errors
/// The endpoint, bearer, model or version is not a seat, or the connector
/// route does not build.
#[doc(hidden)]
pub fn system_one_rung_for_test(
    endpoint: String,
    bearer: String,
    models: Arc<crate::models::ModelRuntime>,
    vault: Arc<Vault>,
    runtime: tokio::runtime::Handle,
) -> anyhow::Result<SystemOneRungForTest> {
    let seat = oneiron_llm::systemone::SystemOneSeat::new(
        endpoint,
        bearer,
        "stub-system-one".to_owned(),
        "1".to_owned(),
    )
    .map_err(|error| anyhow::anyhow!("invalid stub System One seat: {error}"))?;
    Ok(SystemOneRungForTest {
        rung: SystemOneRung {
            vault,
            seat: Arc::new(seat),
            guard: BudgetGuard::new("system-one", 1_000_000, BudgetExhaustionPolicy::Suspend),
            models,
            connector: PaidConnector {
                connector: "system-one".to_owned(),
                route: OfferRoute::new("system-one", "system-one")?,
                locality: ModelLocality::ThirdParty,
                payer: Payer::CustomerKey,
                credential_binding: None,
                catalog_revision: None,
                custody: KeyCustody::T1,
                unit_cost: 1,
                cost_unit: LeaseUnit::tokens(),
                rates: Vec::new(),
            },
            posture: HostingPrivacyPosture::Hosted,
            remote_opt_in: false,
            runtime,
        },
    })
}
