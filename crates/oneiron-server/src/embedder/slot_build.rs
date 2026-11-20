//! Builds the embedder slot from a serve configuration: the slot itself,
//! the paid door of an endpoint provider and of a remote rung, and the
//! startup probe of each endpoint.
use std::sync::Arc;

use super::{EmbedderSlot, admitted, endpoint};
use crate::config::EmbedderConfig;

/// Builds the slot for a resolved serve configuration, probing an endpoint
/// provider before the listener binds.
///
/// A reachable remote that serves the wrong model or the wrong width stops
/// `serve`: filling one vault from two embedding spaces is not recoverable, so
/// it is refused before anything is written. An UNREACHABLE remote is logged and
/// started anyway — the vault answers lexical and graph reads meanwhile, which
/// is the two-tier write rule, not a degraded mode. Every embedding request an
/// endpoint sends is a paid call, its rows written to `receipts`: the primary
/// endpoint's probe, queries and batches, and the remote rung's probe like its
/// batches.
pub(crate) fn build_slot(
    config: Option<&EmbedderConfig>,
    receipts: Arc<dyn oneiron::llm::run_admission::RunReceiptSink>,
) -> anyhow::Result<Option<EmbedderSlot>> {
    build_slot_with_broker(config, receipts, None)
}

/// [`build_slot`], with the vault's credential-broker context a `key_secret`
/// endpoint and remote rung send through, request by request.
pub(crate) fn build_slot_with_broker(
    config: Option<&EmbedderConfig>,
    receipts: Arc<dyn oneiron::llm::run_admission::RunReceiptSink>,
    broker: Option<&crate::models::BrokerContext>,
) -> anyhow::Result<Option<EmbedderSlot>> {
    let Some(config) = config else {
        return Ok(None);
    };
    let Some(slot) = EmbedderSlot::with_broker(config, broker)? else {
        tracing::info!("embedder provider is none; the vault serves at rung 0");
        return Ok(None);
    };
    if let Some(ready) = slot.ready()
        && let Some(http) = ready.as_endpoint()
    {
        admitted::pay_primary(http, config, Arc::clone(&receipts), &slot.background)?;
        match endpoint::probe_endpoint(http) {
            Ok(endpoint::ProbeOutcome::Ready) => {
                tracing::info!("endpoint embedder probe succeeded");
            }
            // The probe's reason is the endpoint's own words; it stays out of the log.
            Ok(endpoint::ProbeOutcome::Unreachable(_reason)) => {
                tracing::warn!(
                    reason = "endpoint_unreachable",
                    "endpoint embedder is unreachable; starting at rung 0 and retrying in the worker"
                );
            }
            Err(error) => anyhow::bail!("{error}"),
        }
    }
    if let Some(remote) = &config.remote {
        let http = endpoint::HttpEmbedder::with_broker(&remote.endpoint_config(config), broker)?;
        http.pay_through(Arc::new(
            admitted::AdmittedRequests::unmetered(
                remote,
                oneiron::embed::Embedder::locality(&*http),
                receipts,
            )?
            .on_background(&slot.background),
        ));
        // Unreachable routes can fall back locally; a reachable wrong model cannot.
        endpoint::probe_endpoint(&http)?;
    }
    tracing::info!(
        provider = slot.provider().as_str(),
        model_id = %slot.config().model_id,
        dimensions = slot.config().dimensions,
        "embedder slot configured"
    );
    Ok(Some(slot))
}
