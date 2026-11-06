//! The charge of a web call on the deploy's backend key (FIX 11604, ARCH-0053
//! §10a): the call is admitted as a paid connector the host pays for, as the
//! embedder's paid requests are, on the calling run's own line when a run
//! calls, else on a meter of its own. Its settlement writes one usage event,
//! a `web:<provider>:<tool>` service of one call from Oneiron cloud usage,
//! which the cloud prices from its own price list; the engine never bills.
//! A known provider cost is a separate fact on that event, with its basis.
//! Calls on the user's own key or through the hub are not ours to charge.
use oneiron::llm::run_admission::{
    CallOutcome, KeyCustody, LeaseUnit, OfferRoute, PaidConnector, Payer, RunAdmission, RunPermit,
};
use oneiron::web_connector::{
    BACKEND_KEY_ENV, WebCallOutcome, WebConnectorUsage, WebCostBasis, WebProvider, WebTool,
};
use oneiron::{BudgetExhaustionPolicy, BudgetGuard, ModelLocality};

use crate::server::SyncServer;
use crate::usage::{UsageServiceCost, UsageServiceCostBasis};

/// The run name a call outside any run is admitted under.
const WEB_RUN: &str = "web-connector";

/// A snapshot of the exact content-free provider cost fact, not a billing table.
const COST_SNAPSHOT_DOMAIN: &[u8] = b"oneiron.usage.web-provider-cost.v1";

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
pub(super) fn settle(server: &SyncServer, permit: RunPermit, usage: &WebConnectorUsage) {
    if let Some(cost) = service_cost(usage)
        && let Some(ledger) = server.vault_usage()
    {
        ledger.record_service_cost(permit.instance(), permit.lease().id(), cost);
    }
    let outcome = if matches!(usage.outcome, WebCallOutcome::Ok { .. }) {
        CallOutcome::UsedCounted(1)
    } else {
        CallOutcome::Failed
    };
    if let Err(denied) = permit.settle(outcome) {
        tracing::error!(%denied, "a web call's settlement was refused");
    }
}

/// Freezes the same provider fact that the web usage row keeps. An absent
/// amount or an unpriced basis never becomes a measured zero.
fn service_cost(usage: &WebConnectorUsage) -> Option<UsageServiceCost> {
    let micro_usd = usage.cost_micro_usd?;
    let (basis, label) = match usage.cost_basis {
        WebCostBasis::Actual => (UsageServiceCostBasis::ProviderReported, "provider_reported"),
        WebCostBasis::Estimated => (UsageServiceCostBasis::Declared, "declared"),
        WebCostBasis::Unpriced => return None,
    };
    let mut digest = blake3::Hasher::new();
    digest.update(COST_SNAPSHOT_DOMAIN);
    for field in [
        Some(usage.provider.as_str()),
        Some(usage.tool.as_str()),
        Some(label),
        Some("USD"),
        usage.provider_request_id.as_deref(),
    ] {
        match field {
            Some(text) => {
                digest.update(&[1]);
                digest.update(&(text.len() as u64).to_le_bytes());
                digest.update(text.as_bytes());
            }
            None => {
                digest.update(&[0]);
            }
        }
    }
    digest.update(&micro_usd.to_le_bytes());
    Some(UsageServiceCost {
        micro_usd,
        basis,
        price_table_snapshot: digest.finalize().to_hex().to_string(),
    })
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
