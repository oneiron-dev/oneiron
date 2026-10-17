//! An endpoint embedder's requests under run admission (ARCH-0053
//! `#run-admission`): the primary endpoint's and a remote rung's alike. Each
//! embedding request an endpoint sends is one paid call of a run that
//! declares nothing. The request is admitted before it is sent, its permit
//! starts just before the send, and it settles after. A refused request
//! fails the embed: a rung's rows are then embedded on device instead, and a
//! primary's stay pending for the worker's next pass. The `/models` listing
//! is metadata, not a paid call, and the in-process local provider sends
//! nothing, so it is not admitted.
use std::sync::Arc;

use oneiron::embed::{Embedder, EmbedderLocality};
use oneiron::llm::run_admission::{
    CallOutcome, KeyCustody, LeaseUnit, OfferRoute, PaidConnector, Payer, RunDenied, RunReceiptSink,
};
use oneiron::{BudgetExhaustionPolicy, BudgetGuard, ModelLocality};

use super::endpoint::{HttpEmbedder, PaidRequests};
use crate::config::remote_embedder::RemoteEmbedderConfig;
use crate::config::{EmbedderConfig, EndpointEmbedderConfig};
use crate::models::undeclared_run;

/// The run each request is admitted under, with the request's own id after
/// it. The primary endpoint's requests share it with a rung's: their
/// connectors' routes and localities tell them apart.
const EMBEDDING_RUN: &str = "remote-embedding";

/// The tokens a text may cost beyond its bytes: the model's special tokens.
const TEXT_OVERHEAD_TOKENS: u64 = 8;

/// What an endpoint's door is admitted by, common to the primary endpoint's
/// section and a remote rung's: where it is, the model it serves and the key
/// it is called with.
#[derive(Clone, Copy)]
pub(crate) struct EndpointFields<'a> {
    endpoint: &'a str,
    model_key: &'a str,
    api_key_env: Option<&'a str>,
}

impl<'a> EndpointFields<'a> {
    /// The primary endpoint's fields, from its section.
    pub(crate) fn primary(config: &'a EndpointEmbedderConfig) -> oneiron::Result<Self> {
        let required = |field: Option<&'a String>, name: &str| {
            field.map(String::as_str).ok_or_else(|| {
                oneiron::Error::InvalidConfig(format!("embedder.{name} is required"))
            })
        };
        Ok(Self {
            endpoint: required(config.endpoint.as_ref(), "endpoint")?,
            model_key: required(config.model_key.as_ref(), "model_key")?,
            api_key_env: config.api_key_env.as_deref(),
        })
    }
}

impl<'a> From<&'a RemoteEmbedderConfig> for EndpointFields<'a> {
    fn from(config: &'a RemoteEmbedderConfig) -> Self {
        Self {
            endpoint: &config.endpoint,
            model_key: &config.model_key,
            api_key_env: config.api_key_env.as_deref(),
        }
    }
}

/// The paid door of one endpoint.
pub(crate) struct AdmittedRequests {
    connector: PaidConnector,
    /// Each request's line. No host pushes one yet, so it has no limit:
    /// each request still takes its permit and writes its rows.
    limit_units: u64,
    receipts: Arc<dyn RunReceiptSink>,
}

impl AdmittedRequests {
    /// The door for the endpoint `fields` names at `locality`, its rows
    /// written to `receipts`, on a line with no limit.
    pub(crate) fn unmetered(
        fields: impl Into<EndpointFields<'_>>,
        locality: EmbedderLocality,
        receipts: Arc<dyn RunReceiptSink>,
    ) -> oneiron::Result<Self> {
        Self::on_line(fields, locality, receipts, u64::MAX)
    }

    pub(super) fn on_line(
        fields: impl Into<EndpointFields<'_>>,
        locality: EmbedderLocality,
        receipts: Arc<dyn RunReceiptSink>,
        limit_units: u64,
    ) -> oneiron::Result<Self> {
        Ok(Self {
            connector: connector(fields.into(), locality)?,
            limit_units,
            receipts,
        })
    }
}

/// Puts `http`, the primary endpoint `config` configures, behind its paid
/// door before it sends anything: its startup probe, its queries and its
/// document batches are each admitted and settled, their rows written to
/// `receipts`. It pays as the section says it is called: with the owner's
/// own key when it names one, keyless on the owner's own device otherwise.
pub(super) fn pay_primary(
    http: &HttpEmbedder,
    config: &EmbedderConfig,
    receipts: Arc<dyn RunReceiptSink>,
) -> oneiron::Result<()> {
    http.pay_through(Arc::new(AdmittedRequests::unmetered(
        EndpointFields::primary(&config.endpoint)?,
        http.locality(),
        receipts,
    )?));
    Ok(())
}

/// The paid connector an endpoint's requests are admitted as: the model it
/// serves, at the endpoint's origin. An endpoint with a key pays with the
/// owner's own key, held in this process (T1). One without is the owner's
/// own device or server.
fn connector(
    config: EndpointFields<'_>,
    locality: EmbedderLocality,
) -> oneiron::Result<PaidConnector> {
    let invalid = |what: &str| oneiron::Error::InvalidConfig(format!("embedder endpoint {what}"));
    let origin = reqwest::Url::parse(config.endpoint)
        .map_err(|_| invalid("endpoint is not a URL"))?
        .origin()
        .ascii_serialization();
    let route = OfferRoute::new("embedder", origin).map_err(|_| invalid("endpoint origin"))?;
    let keyed = config.api_key_env.is_some();
    Ok(PaidConnector {
        connector: format!("embedder:{}", config.model_key),
        route,
        locality: match locality {
            EmbedderLocality::OnDevice => ModelLocality::OnDevice,
            EmbedderLocality::OwnerServer => ModelLocality::OwnServer,
            EmbedderLocality::ThirdParty => ModelLocality::ThirdParty,
        },
        payer: if keyed {
            Payer::CustomerKey
        } else {
            Payer::Local
        },
        credential_binding: config.api_key_env.map(|env| format!("env:{env}")),
        catalog_revision: None,
        custody: if keyed {
            KeyCustody::T1
        } else {
            KeyCustody::Keyless
        },
        unit_cost: 1,
        cost_unit: LeaseUnit::tokens(),
        rates: Vec::new(),
    })
}

/// A request's reservation in tokens: no tokenizer makes more tokens than a
/// text has bytes, plus each text's special tokens. The endpoint reports no
/// usage, so the reservation is also what an answered request settles.
fn estimate(texts: &[&str]) -> u64 {
    texts.iter().fold(0_u64, |tokens, text| {
        let bytes = u64::try_from(text.len()).unwrap_or(u64::MAX);
        tokens
            .saturating_add(bytes)
            .saturating_add(TEXT_OVERHEAD_TOKENS)
    })
}

fn refused(denied: RunDenied) -> oneiron::Error {
    oneiron::Error::UpstreamToolFailure {
        tool: "embedder-remote",
        code: format!("run admission refused the request: {denied}"),
    }
}

impl PaidRequests for AdmittedRequests {
    fn send(
        &self,
        texts: &[&str],
        post: &mut dyn FnMut() -> oneiron::Result<Vec<Vec<f32>>>,
    ) -> oneiron::Result<Vec<Vec<f32>>> {
        let tokens = estimate(texts);
        // A meter of its own per request: its lease ids are the request's,
        // and nothing outlives the call.
        let run = format!("{EMBEDDING_RUN}:{}", oneiron::EntityId::now().to_hex());
        let meter = BudgetGuard::with_reserve_units(
            run.clone(),
            self.limit_units,
            1,
            BudgetExhaustionPolicy::Suspend,
        );
        let run = undeclared_run(run, meter, None, Arc::clone(&self.receipts));
        let permit = run.admit_paid(&self.connector, tokens).map_err(refused)?;
        run.dispatch_paid(permit.lease(), &self.connector)
            .map_err(refused)?;
        let posted = post();
        // The request went out: a failed one keeps its reservation as spend.
        let outcome = match &posted {
            Ok(_) => CallOutcome::Used(tokens),
            Err(_) => CallOutcome::Failed,
        };
        if let Err(denied) = permit.settle(outcome) {
            tracing::error!(%denied, "an embedding request's settlement was refused");
        }
        posted
    }
}
