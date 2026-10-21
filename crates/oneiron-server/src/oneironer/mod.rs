//! The Oneironer slot: the configured tagger, its identity, and the trace of
//! every attempt its worker settled.
//!
//! The engine owns the marker, the queue and every settlement
//! ([`oneiron::tagging`]); this slot only holds the tagger the worker calls.
//! No model name and no label name sits here: identity and labels come from
//! the `[oneironer]` section and the tagger's own model card.
//!
//! Every call goes through the slot's one dispatcher ([`dispatcher`]) to a
//! ready worker, live calls before bulk ones, and comes back with the facts
//! of the worker that ran it. Every worker in a slot serves the same
//! checkpoint, stack, capabilities and decode. The tagging coordinator
//! reaches the same dispatcher through [`ProviderTagger::claim_room`] and
//! [`ProviderTagger::submit`] (FIX 6755), so its markers queue beside every
//! other call.

#[cfg(test)]
use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use oneiron::memory::extraction::{
    EncoderAttempt, EncoderInput, ExtractionEncoder, ExtractionWork,
};
use oneiron::tagging::{TaggingOutcome, TaggingTrace};
use oneiron::{ModelId, embed::EmbedderLocality};

use crate::config::{OneironerConfig, OneironerProvider};
use dispatcher::{Completion, Dispatcher, WorkerSpec};

pub(crate) use dispatcher::DispatchClaim;

mod bundle;
mod dispatcher;
pub(crate) mod endpoint;
pub(crate) mod engines;
mod local;
pub(crate) mod release;

#[cfg(test)]
mod tests;

/// Traces the test log keeps; older ones fall off the front.
#[cfg(test)]
const TRACE_LOG_CAPACITY: usize = 1024;

/// A vault whose model manifest binds another extraction encoder than the
/// one this slot serves. Typed, so the worker stops by name and the markers
/// wait for the bound tagger. The refusal names the binding the vault holds
/// and the checkpoint this server was configured with, never anything the
/// tagger reported.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum EncoderNotSelected {
    #[error(
        "the vault binds extraction_encoder {bound}; this tagger serves checkpoint {serving}, which is not its revision"
    )]
    OtherEncoder { bound: String, serving: String },
    /// The vault binds the checkpoint another configured tier serves.
    #[error(
        "the vault binds extraction_encoder {bound}, which tier {tier:?} serves; this server serves another tier (set oneironer.tier = {tier:?} or --oneironer-tier {tier})"
    )]
    OtherTier { bound: String, tier: String },
}

/// The slot's one facade: every call goes through its dispatcher to a ready
/// worker. Native and HTTP providers share the marker, worker and
/// persistence path.
pub(crate) struct ProviderTagger {
    model: ModelId,
    locality: EmbedderLocality,
    provider: Provider,
    dispatcher: Dispatcher,
}

/// What the slot knows of its provider beside its workers.
enum Provider {
    /// The configured endpoint, probed for its card.
    Endpoint(Arc<endpoint::HttpTagger>),
    /// A native bundle: its card and decoder, as it loaded.
    Local {
        card: endpoint::ModelCard,
        decode_revision: &'static str,
    },
}

impl ProviderTagger {
    /// The facade over `workers`. `pinned` says the slot serves one
    /// configured worker, a named device or an endpoint.
    fn new(
        model: ModelId,
        locality: EmbedderLocality,
        provider: Provider,
        pinned: bool,
        workers: Vec<WorkerSpec>,
    ) -> anyhow::Result<Self> {
        let dispatcher = Dispatcher::new(pinned);
        for worker in workers {
            dispatcher.add(worker)?;
        }
        Ok(Self {
            model,
            locality,
            provider,
            dispatcher,
        })
    }

    pub(crate) fn probe(&self) -> Result<endpoint::ProbeOutcome, endpoint::ProbeError> {
        match &self.provider {
            Provider::Endpoint(tagger) => tagger.probe(),
            Provider::Local { card, .. } => Ok(endpoint::ProbeOutcome::Ready(card.clone())),
        }
    }

    /// Room for one call in `work`'s class on the slot's dispatcher, awaited
    /// with nothing held: the tagging coordinator's claim (FIX 6755). It
    /// shares the pending caps every other call takes room in, and never
    /// refuses; dropped unused, the claim gives its room back.
    pub(crate) fn claim_room(
        &self,
        work: ExtractionWork,
    ) -> impl std::future::Future<Output = DispatchClaim> + Send + 'static {
        self.dispatcher.claim_async(work)
    }

    /// Queues `input` under `claim`, never waiting; the answer comes back
    /// through the returned completion.
    pub(crate) fn submit(&self, claim: DispatchClaim, input: EncoderInput) -> Completion {
        claim.submit(input)
    }

    /// The dispatcher's pending cap of `work`'s class, from its policy: the
    /// bound the tagging coordinator also keeps its resident markers in.
    pub(crate) fn pending_cap(&self, work: ExtractionWork) -> usize {
        dispatcher::pending_cap(work)
    }

    /// The decoder revision a native tagger runs; `None` for an endpoint,
    /// whose card names no decoder.
    pub(crate) fn decode_revision(&self) -> Option<&'static str> {
        match &self.provider {
            Provider::Endpoint(_) => None,
            Provider::Local {
                decode_revision, ..
            } => Some(*decode_revision),
        }
    }
}

impl ExtractionEncoder for ProviderTagger {
    fn model_id(&self) -> &ModelId {
        &self.model
    }

    fn locality(&self) -> EmbedderLocality {
        self.locality
    }

    fn infer(&self, input: &EncoderInput, work: ExtractionWork) -> EncoderAttempt {
        self.dispatcher.call(input, work)
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
    /// The engine a local tagger runs on and how it was picked.
    serving: Option<engines::Serving>,
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

    /// Whether `vault` selects the tagger this slot serves. Its manifest's
    /// `extraction_encoder` binding at the vault's Oneironer route names the
    /// encoder by `name@checkpoint`; the slot serves it when that revision is
    /// the configured checkpoint, whichever provider and engine run it. A
    /// vault with no manifest takes the host's `[oneironer]` section as its
    /// selection. A vault that binds another configured tier's checkpoint is
    /// told which tier serves it. The binding is the vault's: the slot never
    /// picks a generative seat to tag with, and a manifest cannot bind one
    /// (`ModelManifest::validate`).
    pub(crate) fn selected_by(&self, vault: &oneiron::Vault) -> anyhow::Result<()> {
        let Some(manifest) = vault.model_manifest()? else {
            return Ok(());
        };
        let route = vault
            .model_route(oneiron::llm::manifest::ModelSlot::Oneironer)?
            .ok_or_else(|| anyhow::anyhow!("the vault's manifest names no oneironer route"))?;
        let bound = manifest.extraction_encoder(route)?;
        let serving = self.config.checkpoint_sha16.as_deref().unwrap_or_default();
        if bound.revision() != serving {
            if let Some(tier) = self.config.tier_serving(bound.revision()) {
                return Err(EncoderNotSelected::OtherTier {
                    bound: bound.as_str().to_owned(),
                    tier: tier.to_owned(),
                }
                .into());
            }
            return Err(EncoderNotSelected::OtherEncoder {
                bound: bound.as_str().to_owned(),
                serving: serving.to_owned(),
            }
            .into());
        }
        Ok(())
    }

    /// The engine a local tagger was loaded on at startup and how it was
    /// picked; `None` for an endpoint. Not a call's execution: each call's
    /// receipt names the worker that ran it.
    pub(crate) fn serving(&self) -> Option<engines::Serving> {
        self.serving
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
/// The engine rows sit at their XDG/HOME default ([`build_slot_with_rows`]).
pub(crate) fn build_slot(config: Option<&OneironerConfig>) -> anyhow::Result<Option<TaggerSlot>> {
    build_slot_with_rows(config, None)
}

/// [`build_slot`], with the engine rows file the caller names: a managed
/// vault's sits under its data directory, never HOME, XDG, a shared model
/// root or a bundle. `None` keeps the XDG/HOME default.
pub(crate) fn build_slot_with_rows(
    config: Option<&OneironerConfig>,
    rows_location: Option<&Path>,
) -> anyhow::Result<Option<TaggerSlot>> {
    let Some(config) = config.filter(|config| config.is_active()) else {
        return Ok(None);
    };
    config.validate()?;
    let mut serving = None;
    let tagger = match config.provider {
        OneironerProvider::Local => {
            let (tagger, engine) = engines::load(config, rows_location)?;
            tracing::info!(
                engine = %engine.engine.id(),
                pick = engine.pick.as_str(),
                tier = config.tier.as_deref().unwrap_or("-"),
                "oneironer engine serving"
            );
            serving = Some(engine);
            let provider = Provider::Local {
                card: tagger.card(),
                decode_revision: tagger.decode_revision(),
            };
            let model = tagger.model_id().clone();
            // `auto` keeps every ready eligible worker: here the survey's
            // default alone, so no second model is loaded beside it. A named
            // device is the one worker the owner pinned.
            let pinned = engine.pick == engines::Pick::Named;
            let worker = WorkerSpec::local(engine.engine, 0, tagger);
            ProviderTagger::new(
                model,
                EmbedderLocality::OnDevice,
                provider,
                pinned,
                vec![worker],
            )?
        }
        OneironerProvider::Endpoint => {
            let tagger = Arc::new(endpoint::HttpTagger::from_config(config)?);
            let (model, locality) = (tagger.model_id().clone(), tagger.locality());
            let worker = WorkerSpec::endpoint(Arc::clone(&tagger));
            let provider = Provider::Endpoint(tagger);
            ProviderTagger::new(model, locality, provider, true, vec![worker])?
        }
        OneironerProvider::None => return Ok(None),
    };
    let slot = TaggerSlot {
        config: config.clone(),
        tagger: Arc::new(tagger),
        card: Mutex::new(None),
        serving,
        #[cfg(test)]
        traces: Mutex::new(VecDeque::new()),
    };
    match slot.tagger.probe()? {
        endpoint::ProbeOutcome::Ready(card) => {
            // The accepted card names the bundle that serves, so the log
            // alone says which one answers. Its checkpoint and stack are 16
            // lowercase hex digits, never text the tagger has read: an
            // endpoint's passed the probe's checks and a native card hashes
            // its own. `stack_pinned` says whether the owner pinned that
            // stack too; `decode_revision` is the native decoder this build
            // runs, `-` for an endpoint.
            tracing::info!(
                provider = config.provider.as_str(),
                label_count = card.label_count,
                links = card.returns.links,
                checkpoint_sha16 = card.checkpoint_sha16.as_str(),
                stack_sha16 = card.stack_sha16.as_deref().unwrap_or("-"),
                decode_revision = slot.tagger.decode_revision().unwrap_or("-"),
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

/// [`build_slot_with_rows`] off the async runtime: native loading and HTTP
/// are blocking. `rows_location` is the engine rows file, `None` for the
/// XDG/HOME default.
pub(crate) async fn build_slot_off_runtime(
    config: Option<OneironerConfig>,
    rows_location: Option<PathBuf>,
) -> anyhow::Result<Option<TaggerSlot>> {
    let build = move || build_slot_with_rows(config.as_ref(), rows_location.as_deref());
    crate::logging::off_runtime("tagger slot task", build).await?
}
