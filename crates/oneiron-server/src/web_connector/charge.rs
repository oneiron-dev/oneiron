//! The charge of a web call on the deploy's backend key (FIX 11604, ARCH-0053
//! §10a): the call is admitted as a paid connector the host pays for, as the
//! embedder's paid requests are, on the calling run's own line when a run
//! calls, else on a meter of its own. Its settlement writes one usage event,
//! a `web:<provider>:<tool>` service of one call from Oneiron cloud usage,
//! which the cloud prices from its own price list; the engine never bills.
//! Calls on the user's own key or through the hub are not ours to charge.
use oneiron::llm::run_admission::{
    CallOutcome, KeyCustody, LeaseUnit, OfferRoute, PaidConnector, Payer, RunAdmission, RunPermit,
};
use oneiron::web_connector::{BACKEND_KEY_ENV, WebProvider, WebTool};
use oneiron::{BudgetExhaustionPolicy, BudgetGuard, ModelLocality};

use crate::server::SyncServer;

/// The run name a call outside any run is admitted under.
const WEB_RUN: &str = "web-connector";

/// Admits one backend-key call of `tool` on `provider` and opens its
/// dispatch: on `line`, the calling run's own, else on a meter of its own.
/// The permit settles after the send ([`settle`]). A refusal is the reason
/// code the call answers with.
pub(super) fn admit(
    server: &SyncServer,
    line: Option<&RunAdmission>,
    provider: WebProvider,
    tool: WebTool,
) -> Result<RunPermit, &'static str> {
    let connector = paid_connector(provider, tool).ok_or("web_connector_route_invalid")?;
    let own;
    let run = match line {
        Some(line) => line,
        None => {
            // A meter of its own per call: its lease ids are the call's, and
            // nothing outlives it.
            let name = format!("{WEB_RUN}:{}", oneiron::EntityId::now().to_hex());
            let meter = BudgetGuard::with_reserve_units(
                name.clone(),
                u64::MAX,
                1,
                BudgetExhaustionPolicy::Suspend,
            );
            own = server.ai.model_runtime().undeclared_run(name, meter);
            &own
        }
    };
    let permit = run.admit_paid(&connector, 1).map_err(|denied| {
        tracing::warn!(%denied, "a web call's run admission was refused");
        "web_budget_exhausted"
    })?;
    run.dispatch_paid(permit.lease(), &connector)
        .map_err(|denied| {
            tracing::warn!(%denied, "a web call's dispatch was refused");
            "web_budget_exhausted"
        })?;
    Ok(permit)
}

/// Settles a sent call: one call used when the provider answered; a failed
/// one keeps its reservation as spend, as the request went out.
pub(super) fn settle(permit: RunPermit, answered: bool) {
    let outcome = if answered {
        CallOutcome::Used(1)
    } else {
        CallOutcome::Failed
    };
    if let Err(denied) = permit.settle(outcome) {
        tracing::error!(%denied, "a web call's settlement was refused");
    }
}

/// The paid connector a backend-key call is admitted as: one call of one
/// tool at the provider's origin, paid by the host on its environment key
/// (T1). One call is one unit in tokens, so it converts on any run's line.
fn paid_connector(provider: WebProvider, tool: WebTool) -> Option<PaidConnector> {
    let route = OfferRoute::new("web", origin(provider)).ok()?;
    Some(PaidConnector {
        connector: format!("web:{}:{}", provider.as_str(), tool.as_str()),
        route,
        locality: ModelLocality::ThirdParty,
        payer: Payer::Host,
        credential_binding: Some(format!("env:{BACKEND_KEY_ENV}")),
        catalog_revision: None,
        custody: KeyCustody::T1,
        unit_cost: 1,
        cost_unit: LeaseUnit::tokens(),
        rates: Vec::new(),
    })
}

/// The provider's API origin.
fn origin(provider: WebProvider) -> &'static str {
    match provider {
        WebProvider::Tavily => "https://api.tavily.com",
        WebProvider::Exa => "https://api.exa.ai",
        WebProvider::Brave => "https://api.search.brave.com",
        WebProvider::Tinyfish => "https://api.search.tinyfish.ai",
        WebProvider::ContextDev => "https://api.context.dev",
        WebProvider::Octen => "https://api.octen.ai",
    }
}
