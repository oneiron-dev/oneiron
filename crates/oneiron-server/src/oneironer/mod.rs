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
//!
//! On a Mac, the serving build also starts the slot's platform admission
//! ([`Admission`]), which adds the bundle's managed MLX worker ([`mlx`]) and
//! its native Core ML worker ([`coreml`]) to the dispatcher in the
//! background, each once it clears here.

#[cfg(test)]
use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use oneiron::memory::extraction::{
    EncoderAttempt, EncoderInput, ExtractionCaller, ExtractionEncoder, ExtractionWork,
};
use oneiron::tagging::{TaggingOutcome, TaggingTrace};
use oneiron::{ModelId, embed::EmbedderLocality};

use crate::config::{OneironerConfig, OneironerProvider};
use dispatcher::{Completion, Dispatcher, WorkerSpec};
use engines::Admission;
use local::{InferenceWindows, WindowCounter};

pub(crate) use dispatcher::DispatchClaim;

pub(crate) mod bundle;
mod coreml;
mod dispatcher;
pub(crate) mod endpoint;
pub(crate) mod engines;
mod local;
mod mlx;
pub(crate) mod release;
pub(crate) mod wire;

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
    /// The facade over a dispatcher with no worker yet. `pinned` says the
    /// slot serves one configured worker, a named device or an endpoint;
    /// `windows` counts each call's window, `None` for an endpoint, whose
    /// window is its own.
    fn new(
        model: ModelId,
        locality: EmbedderLocality,
        provider: Provider,
        pinned: bool,
        windows: Option<WindowCounter>,
    ) -> Self {
        Self {
            model,
            locality,
            provider,
            dispatcher: Dispatcher::new(pinned, windows),
        }
    }

    pub(crate) fn probe(&self) -> Result<endpoint::ProbeOutcome, endpoint::ProbeError> {
        match &self.provider {
            Provider::Endpoint(tagger) => tagger.probe(),
            Provider::Local { card, .. } => Ok(endpoint::ProbeOutcome::Ready(card.clone())),
        }
    }

    /// Room for one call in `work`'s class on the slot's dispatcher, awaited
    /// with nothing held at `caller`'s turn: the tagging coordinator's claim
    /// (FIX 6755, 9519). It shares the pending caps every other call takes
    /// room in, and never refuses; dropped unused, the claim gives its room
    /// back, and dropped while it waits, it leaves the queue.
    pub(crate) fn claim_room(
        &self,
        work: ExtractionWork,
        caller: ExtractionCaller,
    ) -> impl std::future::Future<Output = DispatchClaim> + Send + 'static {
        self.dispatcher.claim_async(work, caller)
    }

    /// The windows `input` runs as: a tokenizer encode, so a caller runs it
    /// on a blocking unit and hands them to [`Self::submit`] (FIX 7331).
    /// A turn longer than one window runs as parts (FIX 9518).
    pub(crate) fn plan_windows(&self, input: &EncoderInput) -> oneiron::Result<InferenceWindows> {
        self.dispatcher.plan(input)
    }

    /// Queues the call `planned` by [`Self::plan_windows`] under `claim`,
    /// never waiting; the answer comes back through the returned
    /// completion.
    pub(crate) fn submit(
        &self,
        claim: DispatchClaim,
        planned: oneiron::Result<InferenceWindows>,
    ) -> Completion {
        claim.submit_planned(planned)
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

/// The slot's close, held apart from the slot by a teardown that outlives
/// its borrow (FIX 7383). Serve and managed teardown close the slot once
/// tagging has ended, so each platform child is shut down and reaped before
/// the process exits, not left to the OS.
pub(crate) struct SlotClose(Arc<ProviderTagger>);

impl SlotClose {
    /// Closes the slot's dispatcher on a blocking unit, which waits for each
    /// supervised child's shutdown and reap.
    pub(crate) async fn close(self) {
        let tagger = self.0;
        let closed = tokio::task::spawn_blocking(move || tagger.dispatcher.close()).await;
        if let Err(error) = closed {
            tracing::warn!(
                panicked = error.is_panic(),
                "oneironer slot close ended early"
            );
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

    /// A call that names no caller shares its room as this server's own.
    fn infer(&self, input: &EncoderInput, work: ExtractionWork) -> EncoderAttempt {
        self.dispatcher
            .call(input, work, &ExtractionCaller::new("host"))
    }

    fn infer_for(
        &self,
        input: &EncoderInput,
        work: ExtractionWork,
        caller: &ExtractionCaller,
    ) -> EncoderAttempt {
        self.dispatcher.call(input, work, caller)
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
    /// The platform admission the serving build starts, until it does.
    platforms: Option<Admission>,
    /// The test door onto the traces the worker emitted, bounded.
    #[cfg(test)]
    traces: Mutex<VecDeque<LoggedTrace>>,
}

impl TaggerSlot {
    pub(crate) fn config(&self) -> &OneironerConfig {
        &self.config
    }

    /// The slot's close, for teardown ([`SlotClose`]).
    pub(crate) fn closer(&self) -> SlotClose {
        SlotClose(Arc::clone(&self.tagger))
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

    /// Starts the slot's platform admission once, on its own thread (FIX
    /// 6755 slice 3). Only the serving build calls it, never `init`'s
    /// check; a later call starts nothing.
    fn start_platform_workers(&mut self) {
        if let Some(admission) = self.platforms.take() {
            admission.start();
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
/// and loaded before the listener binds. A local bundle whose manifest is
/// not format 2 builds nothing either: its typed refusal is logged once, and
/// the server serves without a tagger, its markers waiting for a bundle that
/// loads (FIX 6755). Any other load failure stops `serve`, as does a
/// reachable endpoint that is not the configured tagger; an unreachable one
/// is probed again. The engine rows sit at their XDG/HOME default
/// ([`build_slot_with_rows`]).
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
    build_slot_inner(config, rows_location, true)
}

/// [`build_slot`], without starting a worker thread or its warm-up call:
/// what init validates. It loads and checks the same bundle, engine and
/// probe, and reports the same serving engine, but starts no worker.
pub(crate) fn build_slot_for_validation(
    config: Option<&OneironerConfig>,
) -> anyhow::Result<Option<TaggerSlot>> {
    build_slot_inner(config, None, false)
}

fn build_slot_inner(
    config: Option<&OneironerConfig>,
    rows_location: Option<&Path>,
    start_workers: bool,
) -> anyhow::Result<Option<TaggerSlot>> {
    let Some(config) = config.filter(|config| config.is_active()) else {
        return Ok(None);
    };
    config.validate()?;
    let (mut serving, mut platforms) = (None, None);
    let tagger = match config.provider {
        OneironerProvider::Local => {
            let (tagger, engine) = match engines::load(config, rows_location) {
                Ok(loaded) => loaded,
                Err(error) => {
                    let format = error
                        .chain()
                        .find_map(|cause| cause.downcast_ref::<bundle::BundleFormat>());
                    if let Some(format) = format {
                        tracing::error!(
                            error = %format,
                            "oneironer bundle refused; serving without the tagger"
                        );
                        return Ok(None);
                    }
                    return Err(error);
                }
            };
            tracing::info!(
                engine = %engine.engine.id(),
                pick = engine.pick.as_str(),
                tier = config.tier.as_deref().unwrap_or("-"),
                "oneironer engine serving"
            );
            serving = Some(engine);
            let card = tagger.card();
            let provider = Provider::Local {
                card: card.clone(),
                decode_revision: tagger.decode_revision(),
            };
            let model = tagger.model_id().clone();
            // `auto` keeps every ready eligible worker: here the survey's
            // default alone, so no second model is loaded beside it. A named
            // device is the one worker the owner pinned.
            let pinned = engine.pick == engines::Pick::Named;
            let windows = tagger.window_counter();
            let tagger = if start_workers {
                let worker = WorkerSpec::local(engine.engine, tagger);
                let tagger = ProviderTagger::new(
                    model,
                    EmbedderLocality::OnDevice,
                    provider,
                    pinned,
                    Some(windows),
                );
                // The Candle baseline the rows chose, or the device the owner
                // named, ranks first (FIX 6755).
                let worker = tagger.dispatcher.add(worker)?;
                tagger.dispatcher.publish_rank(worker, 0);
                // A platform runtime joins it only from the serving build, in
                // the background, and never beside a pinned engine.
                let handle = tagger.dispatcher.handle();
                platforms = Admission::new(config, rows_location, handle, engine, worker, card);
                tagger
            } else {
                let _ = WorkerSpec::validate_local(engine.engine, &tagger);
                ProviderTagger::new(
                    model,
                    EmbedderLocality::OnDevice,
                    provider,
                    pinned,
                    Some(windows),
                )
            };
            tagger
        }
        OneironerProvider::Endpoint => {
            let http = Arc::new(endpoint::HttpTagger::from_config(config)?);
            let (model, locality) = (http.model_id().clone(), http.locality());
            let checkpoint = config.checkpoint_sha16.as_deref().unwrap_or_default();
            let tagger = if start_workers {
                let worker = WorkerSpec::endpoint(Arc::clone(&http), checkpoint);
                let tagger =
                    ProviderTagger::new(model, locality, Provider::Endpoint(http), true, None);
                tagger.dispatcher.add(worker)?;
                tagger
            } else {
                let _ = WorkerSpec::validate_endpoint(checkpoint);
                ProviderTagger::new(model, locality, Provider::Endpoint(http), true, None)
            };
            tagger
        }
        OneironerProvider::None => return Ok(None),
    };
    let slot = TaggerSlot {
        config: config.clone(),
        tagger: Arc::new(tagger),
        card: Mutex::new(None),
        serving,
        platforms,
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
/// XDG/HOME default. This is the serving build, `serve`'s and a managed
/// vault's: it starts the slot's platform admission, which never holds back
/// the listener (FIX 6755 slice 3).
pub(crate) async fn build_slot_off_runtime(
    config: Option<OneironerConfig>,
    rows_location: Option<PathBuf>,
) -> anyhow::Result<Option<TaggerSlot>> {
    let build = move || {
        let mut slot = build_slot_with_rows(config.as_ref(), rows_location.as_deref())?;
        if let Some(slot) = slot.as_mut() {
            slot.start_platform_workers();
        }
        Ok(slot)
    };
    crate::logging::off_runtime("tagger slot task", build).await?
}
