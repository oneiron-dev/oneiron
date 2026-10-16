//! The Oneironer slot: the configured tagger, its identity, and the trace of
//! every attempt its worker settled.
//!
//! The engine owns the marker, the queue and every settlement
//! ([`oneiron::tagging`]); this slot only holds the tagger the worker calls.
//! No model name and no label name sits here: identity and labels come from
//! the `[oneironer]` section and the tagger's own model card.

#[cfg(test)]
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use oneiron::memory::extraction::{EncoderInput, EncoderOutput, ExtractionEncoder};
use oneiron::tagging::{TaggingOutcome, TaggingTrace};
use oneiron::{ModelId, embed::EmbedderLocality};

use crate::config::{OneironerConfig, OneironerProvider};

pub(crate) mod endpoint;
mod local;

#[cfg(test)]
mod tests;

/// Traces the test log keeps; older ones fall off the front.
#[cfg(test)]
const TRACE_LOG_CAPACITY: usize = 1024;

/// Native and HTTP providers share the marker, worker and persistence path.
pub(crate) enum ProviderTagger {
    Endpoint(endpoint::HttpTagger),
    Local(Box<local::LocalTagger>),
}

impl ProviderTagger {
    pub(crate) fn probe(&self) -> Result<endpoint::ProbeOutcome, endpoint::ProbeError> {
        match self {
            Self::Endpoint(tagger) => tagger.probe(),
            Self::Local(tagger) => Ok(endpoint::ProbeOutcome::Ready(tagger.card())),
        }
    }
}

impl ExtractionEncoder for ProviderTagger {
    fn model_id(&self) -> &ModelId {
        match self {
            Self::Endpoint(tagger) => tagger.model_id(),
            Self::Local(tagger) => tagger.model_id(),
        }
    }

    fn locality(&self) -> EmbedderLocality {
        match self {
            Self::Endpoint(tagger) => tagger.locality(),
            Self::Local(tagger) => tagger.locality(),
        }
    }

    fn infer(&self, input: &EncoderInput) -> oneiron::Result<EncoderOutput> {
        match self {
            Self::Endpoint(tagger) => tagger.infer(input),
            Self::Local(tagger) => tagger.infer(input),
        }
    }
}

/// One trace as a test observes it.
#[cfg(test)]
#[derive(Clone, Debug)]
pub(crate) struct LoggedTrace {
    pub(crate) trace: TaggingTrace,
    /// When the worker logged it, for the write-to-trace measurement.
    pub(crate) at: std::time::Instant,
}

/// The slot on the server: what is configured and the tagger.
pub(crate) struct TaggerSlot {
    config: OneironerConfig,
    tagger: Arc<ProviderTagger>,
    card: Mutex<Option<endpoint::ModelCard>>,
    /// The test door onto the traces the worker emitted, bounded.
    #[cfg(test)]
    traces: Mutex<VecDeque<LoggedTrace>>,
}

impl TaggerSlot {
    pub(crate) fn config(&self) -> &OneironerConfig {
        &self.config
    }

    pub(crate) fn tagger(&self) -> &Arc<ProviderTagger> {
        &self.tagger
    }

    /// The last model card a probe accepted.
    pub(crate) fn card(&self) -> Option<endpoint::ModelCard> {
        self.card.lock().ok().and_then(|card| card.clone())
    }

    pub(crate) fn accept_card(&self, card: endpoint::ModelCard) {
        if let Ok(mut slot) = self.card.lock() {
            *slot = Some(card);
        }
    }

    /// Emits one trace as its marker settles: one structured event per
    /// attempt. A trace names the turn, the tagger and the outcome, and
    /// carries no vault text.
    pub(crate) fn log(&self, trace: &TaggingTrace) {
        let event = serde_json::to_string(trace).unwrap_or_default();
        if matches!(
            trace.outcome,
            TaggingOutcome::Failed { .. } | TaggingOutcome::Unreadable
        ) {
            tracing::warn!(trace = %event, "tagging attempt failed");
        } else {
            tracing::info!(trace = %event, "tagging attempt settled");
        }
        #[cfg(test)]
        if let Ok(mut log) = self.traces.lock() {
            if log.len() == TRACE_LOG_CAPACITY {
                log.pop_front();
            }
            log.push_back(LoggedTrace {
                trace: trace.clone(),
                at: std::time::Instant::now(),
            });
        }
    }

    /// The emitted traces, oldest first.
    #[cfg(test)]
    pub(crate) fn traces(&self) -> Vec<LoggedTrace> {
        self.traces
            .lock()
            .map(|log| log.iter().cloned().collect())
            .unwrap_or_default()
    }
}

/// Builds the slot for a resolved section, probing the tagger before the
/// listener binds.
///
/// `None` and an absent section build nothing. Native artifacts are verified
/// and loaded before the listener binds. A reachable endpoint that is not
/// the configured tagger stops `serve`; an unreachable one is probed again.
pub(crate) fn build_slot(config: Option<&OneironerConfig>) -> anyhow::Result<Option<TaggerSlot>> {
    let Some(config) = config.filter(|config| config.is_active()) else {
        return Ok(None);
    };
    config.validate()?;
    let tagger = match config.provider {
        OneironerProvider::Local => {
            ProviderTagger::Local(Box::new(local::LocalTagger::load(config)?))
        }
        OneironerProvider::Endpoint => {
            ProviderTagger::Endpoint(endpoint::HttpTagger::from_config(config)?)
        }
        OneironerProvider::None => return Ok(None),
    };
    let slot = TaggerSlot {
        config: config.clone(),
        tagger: Arc::new(tagger),
        card: Mutex::new(None),
        #[cfg(test)]
        traces: Mutex::new(VecDeque::new()),
    };
    match slot.tagger.probe()? {
        endpoint::ProbeOutcome::Ready(card) => {
            // The card's stack is the tagger's own string: with no pin to
            // compare it to, it could be anything the tagger has read, so the
            // log says only whether one was pinned.
            tracing::info!(
                provider = config.provider.as_str(),
                label_count = card.label_count,
                links = card.returns.links,
                stack_pinned = config.stack_sha16.is_some(),
                "tagger probe succeeded"
            );
            slot.accept_card(card);
        }
        endpoint::ProbeOutcome::Unreachable(reason) => {
            tracing::warn!(
                reason,
                "tagger is unreachable; writes commit their markers and the worker keeps probing"
            );
        }
    }
    tracing::info!(mode = config.mode.as_str(), "oneironer slot configured");
    Ok(Some(slot))
}

/// [`build_slot`] off the async runtime: native loading and HTTP are blocking.
pub(crate) async fn build_slot_off_runtime(
    config: Option<OneironerConfig>,
) -> anyhow::Result<Option<TaggerSlot>> {
    crate::logging::off_runtime("tagger slot task", move || build_slot(config.as_ref())).await?
}
