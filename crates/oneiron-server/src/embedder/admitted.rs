//! A remote rung under run admission (ARCH-0053 `#run-admission`): each batch
//! the rung sends is one paid call of a run that declares nothing. The batch
//! is admitted on the rung's meter before the authenticated send, starts its
//! permit just before the send, and settles after. A refused batch fails the
//! rung, so the reconciler embeds it on device instead. On-device embedding
//! is not admitted.
use std::sync::Arc;

use oneiron::embed::{Embedder, EmbedderLocality, PendingEmbeddingInput, payload_text};
use oneiron::llm::run_admission::{
    CallOutcome, KeyCustody, LeaseUnit, OfferRoute, PaidConnector, Payer, RunDenied,
    RunReceiptSink,
};
use oneiron::{BudgetExhaustionPolicy, BudgetGuard, ModelLocality};

use crate::config::remote_embedder::RemoteEmbedderConfig;
use crate::models::undeclared_run;

/// The run each remote batch is admitted under, one run per batch.
const EMBEDDING_RUN: &str = "remote-embedding";

/// The tokens an input may cost beyond its text's bytes: the instruction a
/// wire adds and the model's own special tokens.
const INPUT_OVERHEAD_TOKENS: u64 = 16;

/// The remote rung's embedder, each batch admitted and settled.
pub(crate) struct AdmittedEmbedder {
    inner: Arc<dyn Embedder>,
    connector: PaidConnector,
    meter: BudgetGuard,
    receipts: Arc<dyn RunReceiptSink>,
}

impl AdmittedEmbedder {
    /// `inner` sent as `config`'s rung, on a meter with no limit: each batch
    /// takes its permit and writes its rows, and no line refuses it until a
    /// host pushes one.
    pub(crate) fn unmetered(
        inner: Arc<dyn Embedder>,
        config: &RemoteEmbedderConfig,
        receipts: Arc<dyn RunReceiptSink>,
    ) -> oneiron::Result<Self> {
        let meter = BudgetGuard::with_reserve_units(
            EMBEDDING_RUN,
            u64::MAX,
            1,
            BudgetExhaustionPolicy::Suspend,
        );
        Self::new(inner, config, meter, receipts)
    }

    pub(super) fn new(
        inner: Arc<dyn Embedder>,
        config: &RemoteEmbedderConfig,
        meter: BudgetGuard,
        receipts: Arc<dyn RunReceiptSink>,
    ) -> oneiron::Result<Self> {
        let connector = connector(config, inner.locality())?;
        Ok(Self {
            inner,
            connector,
            meter,
            receipts,
        })
    }
}

/// The paid connector a remote rung's batches are admitted as: the model it
/// serves, at the endpoint's origin. A rung with a key pays with the owner's
/// own key, held in this process (T1); one without is the owner's own server.
fn connector(
    config: &RemoteEmbedderConfig,
    locality: EmbedderLocality,
) -> oneiron::Result<PaidConnector> {
    let invalid = |what: &str| oneiron::Error::InvalidConfig(format!("embedder.remote {what}"));
    let origin = reqwest::Url::parse(&config.endpoint)
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
        credential_binding: config.api_key_env.as_ref().map(|env| format!("env:{env}")),
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

/// A batch's reservation in tokens: no tokenizer makes more tokens than its
/// text has bytes, plus each input's overhead. The endpoint reports no usage,
/// so the reservation is also what an answered batch settles.
fn estimate(inputs: &[PendingEmbeddingInput]) -> oneiron::Result<u64> {
    inputs.iter().try_fold(0_u64, |tokens, input| {
        let text = payload_text(&input.payload)?;
        let bytes = u64::try_from(text.len()).unwrap_or(u64::MAX);
        Ok(tokens
            .saturating_add(bytes)
            .saturating_add(INPUT_OVERHEAD_TOKENS))
    })
}

fn refused(denied: RunDenied) -> oneiron::Error {
    oneiron::Error::UpstreamToolFailure {
        tool: "embedder-remote",
        code: format!("run admission refused the batch: {denied}"),
    }
}

impl Embedder for AdmittedEmbedder {
    fn model_id(&self) -> &str {
        self.inner.model_id()
    }

    fn dimensions(&self) -> usize {
        self.inner.dimensions()
    }

    fn locality(&self) -> EmbedderLocality {
        self.inner.locality()
    }

    fn embed(&self, inputs: &[PendingEmbeddingInput]) -> oneiron::Result<Vec<Vec<f32>>> {
        if inputs.is_empty() {
            return Ok(Vec::new());
        }
        let tokens = estimate(inputs)?;
        let run = undeclared_run(
            EMBEDDING_RUN,
            self.meter.clone(),
            Arc::clone(&self.receipts),
        );
        let permit = run.admit_paid(&self.connector, tokens).map_err(refused)?;
        run.dispatch_paid(permit.lease(), &self.connector)
            .map_err(refused)?;
        let (embedded, outcome) = match self.inner.embed(inputs) {
            Ok(vectors) => (Ok(vectors), CallOutcome::Used(tokens)),
            // The send started: a failed batch keeps its reservation as spend.
            Err(error) => (Err(error), CallOutcome::Failed),
        };
        if let Err(denied) = permit.settle(outcome) {
            tracing::error!(%denied, "a remote embedding batch's settlement was refused");
        }
        embedded
    }
}
