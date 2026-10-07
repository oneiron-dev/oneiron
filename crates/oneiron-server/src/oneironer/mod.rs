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

use oneiron::tagging::{TaggingOutcome, TaggingTrace};

use crate::config::{OneironerConfig, OneironerMode, OneironerProvider};

pub(crate) mod endpoint;

#[cfg(test)]
mod tests;

/// Traces the test log keeps; older ones fall off the front.
#[cfg(test)]
const TRACE_LOG_CAPACITY: usize = 1024;

/// A configured slot this build cannot serve yet. Typed, so `serve` and
/// `init` refuse it by name instead of starting a slot that tags nothing.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum TaggerNotBuilt {
    #[error(
        "oneironer.provider = \"local\" is not built yet; run a tagger server on this machine and set provider = \"endpoint\""
    )]
    LocalProvider,
    #[error(
        "oneironer.mode = \"save\" is not built yet (ONE-2167); set mode = \"shadow\" to tag without saving"
    )]
    SaveMode,
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
    tagger: Arc<endpoint::HttpTagger>,
    card: Mutex<Option<endpoint::ModelCard>>,
    /// The test door onto the traces the worker emitted, bounded.
    #[cfg(test)]
    traces: Mutex<VecDeque<LoggedTrace>>,
}

impl TaggerSlot {
    pub(crate) fn config(&self) -> &OneironerConfig {
        &self.config
    }

    pub(crate) fn tagger(&self) -> &Arc<endpoint::HttpTagger> {
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
/// `None` and an absent section build nothing. The local provider and save
/// mode are refused, typed. A reachable tagger that is not the configured one
/// stops `serve`; an unreachable one is logged and the worker probes again.
pub(crate) fn build_slot(config: Option<&OneironerConfig>) -> anyhow::Result<Option<TaggerSlot>> {
    let Some(config) = config.filter(|config| config.is_active()) else {
        return Ok(None);
    };
    if config.provider == OneironerProvider::Local {
        return Err(TaggerNotBuilt::LocalProvider.into());
    }
    if config.mode == OneironerMode::Save {
        return Err(TaggerNotBuilt::SaveMode.into());
    }
    let tagger = endpoint::HttpTagger::from_config(config)?;
    let slot = TaggerSlot {
        config: config.clone(),
        tagger: Arc::new(tagger),
        card: Mutex::new(None),
        #[cfg(test)]
        traces: Mutex::new(VecDeque::new()),
    };
    match slot.tagger.probe()? {
        endpoint::ProbeOutcome::Ready(card) => {
            tracing::info!(
                url = slot.tagger.base(),
                label_count = card.label_count,
                links = card.returns.links,
                engine = card.engine.as_deref().unwrap_or("unreported"),
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

/// [`build_slot`] on a blocking thread: the probe is a blocking HTTP call.
pub(crate) async fn build_slot_off_runtime(
    config: Option<OneironerConfig>,
) -> anyhow::Result<Option<TaggerSlot>> {
    tokio::task::spawn_blocking(move || build_slot(config.as_ref()))
        .await
        .map_err(|error| anyhow::anyhow!("tagger slot task failed: {error}"))?
}
