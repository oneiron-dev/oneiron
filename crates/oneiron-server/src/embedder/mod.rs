//! The embedder provider slot.
//!
//! The engine owns the whole embedding contract — the queue, the leases, the
//! f16 rows, the `model_id` pin — and injects nothing. This module is the
//! host side of that seam: one slot, three providers, one trait object handed
//! to the reconciler.
//!
//! Everything except "run the forward" is shared, and shared on purpose: the
//! space id, the text projection, the query instruction, the numerics contract
//! on returned vectors. Two providers that differed in any of those would open
//! two embedding spaces inside one vault.

mod admitted;
mod endpoint;
mod remote;
pub(crate) use local::prepare as prepare_local;
pub(crate) use remote::build_remote_rung;
mod local;
pub(crate) mod serve;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use oneiron::config::VectorEvidenceFloors;
use oneiron::embed::{Embedder, EmbedderLocality, PendingEmbeddingInput, payload_text};
use serde::Serialize;

use crate::config::{EmbedderConfig, EmbedderProvider};

/// An embedder that can also embed a QUERY.
///
/// The engine's [`Embedder`] covers the write path only: it embeds pending
/// rows. The read path needs the query side of the same model, with the
/// instruction prefix the model asks for, so the slot carries this narrower
/// trait and hands the engine the wider one.
pub(crate) trait QueryEmbedder: Embedder {
    fn embed_query(&self, text: &str) -> oneiron::Result<Vec<f32>>;
    /// Inputs the provider had to shorten since it started serving. The worker
    /// reports it per pass; an operator who sees it climb has their token cap
    /// set below their corpus.
    fn truncations(&self) -> u64;

    /// The endpoint provider, for the one thing only it has: a startup probe
    /// against a remote. Every other provider answers `None` and the probe is
    /// skipped, rather than the slot downcasting on a provider tag.
    fn as_endpoint(&self) -> Option<&endpoint::HttpEmbedder> {
        None
    }

    /// The model this provider loaded on this host, when it loads one: an
    /// endpoint's model runs elsewhere and answers `None`.
    fn loaded(&self) -> Option<&LoadedModel> {
        None
    }
}

/// The model a local provider loaded, as it loaded it: what makes this
/// vault's vectors once the vault has admitted it, apart from what config
/// asks for and what the vault pins.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct LoadedModel {
    pub(crate) repo: String,
    pub(crate) revision: String,
    /// The output width the model's module chain was checked to give.
    pub(crate) dimensions: usize,
    /// Where it runs: `cpu`, `metal` or `cuda`, never `auto`.
    pub(crate) device: &'static str,
    /// How its weights are held: `q8_0`, or `none` for the checkpoint's own
    /// bf16.
    pub(crate) quant: &'static str,
    /// How its files were checked: `pinned_digests` (each file's size and
    /// sha256 at the pinned revision), `unpinned` (a revision this build
    /// pins no digests for) or `model_dir` (an operator's directory, read as
    /// found).
    pub(crate) artifacts: &'static str,
}

/// Whether the slot serves dense recall, and on what.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum DenseState {
    /// The vault admitted the provider; `loaded` is its local model, if it
    /// loaded one.
    Ready { loaded: Option<LoadedModel> },
    /// Not admitted yet, and nothing refused so far: the model is still
    /// downloading or loading, or the worker has not reached it.
    Loading,
    /// The last load or admission failed, for this reason. The worker tries
    /// again.
    Refused { reason: String },
}

/// Identity and numerics every provider shares.
#[derive(Clone, Debug)]
pub(crate) struct EmbedderCommon {
    /// `org/name@revision` — the vault's embedding space.
    pub(crate) model_id: String,
    pub(crate) dimensions: usize,
    pub(crate) query_instruction: String,
}

impl EmbedderCommon {
    fn from_config(config: &EmbedderConfig) -> Self {
        Self {
            model_id: config.model_id.clone(),
            dimensions: config.dimensions,
            query_instruction: config.query_instruction.clone().unwrap_or_default(),
        }
    }

    /// The query text an endpoint embeds: the configured instruction, if any,
    /// then the query.
    fn query_text(&self, text: &str) -> String {
        format!("{}{text}", self.query_instruction)
    }

    /// The document text a provider embeds: the engine's canonical projection,
    /// with no instruction of the server's own. Only a prompt the model itself
    /// declares for documents goes in front of it, and only the local provider,
    /// which reads the model's files, knows one.
    fn document_text(&self, input: &PendingEmbeddingInput) -> oneiron::Result<String> {
        let text = payload_text(&input.payload)?;
        if text.chars().all(|c| c.is_whitespace() || c.is_control()) {
            // A row of whitespace and control characters alone has nothing to
            // embed, and a zero vector would be a lie that retrieval would then
            // rank. The engine never leases such a row: it retires it as stale
            // work, so the rest of its batch still fills.
            return Err(oneiron::Error::InvariantViolation(
                "a pending embedding row projected to empty text",
            ));
        }
        Ok(text.into_owned())
    }

    /// The numerics contract on every vector leaving any provider.
    ///
    /// Exactly `dimensions` finite components, L2-normalised, and rounded
    /// through `f16` — which is what the engine stores, so a provider that
    /// returned unrounded values would report a vector the vault does not
    /// hold, and the row encoder would be the first to find out.
    fn finish_vector(&self, mut vector: Vec<f32>) -> oneiron::Result<Vec<f32>> {
        if vector.len() != self.dimensions {
            return Err(oneiron::Error::DimensionMismatch {
                expected: self.dimensions,
                got: vector.len(),
            });
        }
        for (index, &value) in vector.iter().enumerate() {
            if !value.is_finite() {
                return Err(oneiron::Error::InvalidVector { index, value });
            }
        }
        let norm = vector.iter().map(|v| v * v).sum::<f32>().sqrt();
        if !norm.is_finite() || norm <= 0.0 {
            return Err(oneiron::Error::InvalidVector {
                index: 0,
                value: norm,
            });
        }
        for value in &mut vector {
            let scaled = *value / norm;
            let narrowed = half::f16::from_f32(scaled);
            if !narrowed.is_finite() {
                return Err(oneiron::Error::InvalidVector {
                    index: 0,
                    value: scaled,
                });
            }
            *value = narrowed.to_f32();
        }
        Ok(vector)
    }
}

/// What a vault admits a provider by ([`EmbedderSlot::ensure_ready`]).
pub(crate) struct Admission<'a> {
    /// How the provider makes vectors, when it says: held to the vault's pin.
    pub(crate) transform: Option<&'a str>,
    /// Where vector evidence starts in the space it serves.
    pub(crate) evidence: VectorEvidenceFloors,
}

impl Admission<'_> {
    /// Admits into `vault`: the transform against its pin, which a vault
    /// that has none adopts, then the floors its context packs are judged by.
    pub(crate) fn into_vault(self, vault: &oneiron::Vault) -> oneiron::Result<()> {
        if let Some(transform) = self.transform {
            vault.adopt_embedding_transform(transform)?;
        }
        vault.set_vector_evidence(self.evidence)
    }
}

/// Why a query could not be embedded.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum EmbedQueryRefusal {
    /// No `[embedder]` section, or `provider = "none"`.
    NotConfigured,
    /// Configured, but the provider is not serving yet — the local model is
    /// still downloading, verifying or loading. Writes still land; vectors
    /// fill later (the two-tier write rule).
    NotReady,
    /// The provider is serving but this call failed. The cause is logged where
    /// it happened; the caller gets no detail about a remote or a device.
    Failed,
}

/// The slot on the server: what is configured, and whether it is serving yet.
pub(crate) struct EmbedderSlot {
    config: EmbedderConfig,
    /// Filled the first time a provider is ready.
    ///
    /// The local provider needs artifacts it may have to download, so it is
    /// built by the worker and not at boot: a vault whose model has never been
    /// fetched still opens, still answers BM25, and starts filling vectors when
    /// the fetch succeeds. A `OnceLock` FIELD, never a process static — the
    /// slot belongs to the server that owns the vault.
    ready: OnceLock<Arc<dyn QueryEmbedder>>,
    /// Fetches and verifies the local provider's artifacts. A field for the
    /// same reason `ready` is one: it belongs to this server, and it has to
    /// outlive the individual load attempts the worker makes.
    models: local::model_manager::ModelManager,
    /// The vault has admitted how the provider makes vectors. An endpoint is
    /// built at boot but answers no query until the worker has admitted it,
    /// as a local model answers none before it has loaded and been admitted.
    admitted: AtomicBool,
    /// The space the vault admitted from the provider, which a remote rung's
    /// answers are held to ([`Self::remote_rung`]); set again with the
    /// vault's floors on every admission.
    rung_hold: Arc<Mutex<remote::RungHold>>,
    /// Why the last load or admission failed, cleared by the next success.
    refusal: Mutex<Option<String>>,
}

impl EmbedderSlot {
    /// Builds the slot for a resolved section, or `None` at rung 0.
    ///
    /// The endpoint provider is ready on return: it holds an HTTP client and
    /// no artifacts. The local provider is not, by design.
    pub(crate) fn from_config(config: &EmbedderConfig) -> oneiron::Result<Option<Self>> {
        crate::config::remote_embedder::validate_remote(config)?;
        if !config.is_active() {
            return Ok(None);
        }
        let slot = Self {
            config: config.clone(),
            ready: OnceLock::new(),
            models: local::model_manager::ModelManager::default(),
            admitted: AtomicBool::new(false),
            rung_hold: Arc::default(),
            refusal: Mutex::new(None),
        };
        if config.provider == EmbedderProvider::Endpoint {
            let embedder = endpoint::HttpEmbedder::from_config(config)?;
            let _ = slot.ready.set(embedder as Arc<dyn QueryEmbedder>);
        }
        Ok(Some(slot))
    }

    pub(crate) fn config(&self) -> &EmbedderConfig {
        &self.config
    }

    pub(crate) fn provider(&self) -> EmbedderProvider {
        self.config.provider
    }

    /// The provider, if it is serving.
    pub(crate) fn ready(&self) -> Option<&Arc<dyn QueryEmbedder>> {
        self.ready.get()
    }

    /// Fetches the local model's artifacts from somewhere other than Hugging
    /// Face. Test-only: it is how a row exercises the fetch path without
    /// leaving the host.
    #[cfg(test)]
    pub(crate) fn with_model_source(mut self, base_url: &str) -> Self {
        self.models = local::model_manager::ModelManager::with_base_url(base_url);
        self
    }

    /// Truncations the serving provider has counted, or `None` before it serves.
    pub(crate) fn truncations(&self) -> Option<u64> {
        self.ready.get().map(|embedder| embedder.truncations())
    }

    /// Makes the provider ready, doing whatever that costs.
    ///
    /// For the local provider that is the first-use download, the sha256
    /// verification and the load-plus-quantise, so this blocks for seconds to
    /// minutes and belongs on a blocking thread. Idempotent: once ready, it
    /// returns the same provider.
    ///
    /// `admit` sees the loaded model's transform descriptor and evidence
    /// floors before the provider serves anything, and its refusal leaves the
    /// slot not ready: a model whose files only arrived after the vault opened
    /// is checked against the vault's pinned transform here rather than at
    /// open. An endpoint that says what it serves (`embedder serve`) is
    /// checked the same way, once its listing has been read, and must name the
    /// vault's model as the one it loaded; its floors are known only then.
    pub(crate) fn ensure_ready(
        &self,
        admit: impl FnOnce(Admission<'_>) -> oneiron::Result<()>,
    ) -> oneiron::Result<Arc<dyn QueryEmbedder>> {
        let ready = self.make_ready(admit);
        *self
            .refusal
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) =
            ready.as_ref().err().map(ToString::to_string);
        ready
    }

    /// Whether dense recall runs on this slot now, and on what.
    pub(crate) fn dense_state(&self) -> DenseState {
        let refusal = self
            .refusal
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        let serving = self
            .ready
            .get()
            .filter(|_| self.admitted.load(Ordering::Acquire));
        match (serving, refusal) {
            (Some(embedder), _) => DenseState::Ready {
                loaded: embedder.loaded().cloned(),
            },
            (None, Some(reason)) => DenseState::Refused { reason },
            (None, None) => DenseState::Loading,
        }
    }

    fn make_ready(
        &self,
        admit: impl FnOnce(Admission<'_>) -> oneiron::Result<()>,
    ) -> oneiron::Result<Arc<dyn QueryEmbedder>> {
        if let Some(ready) = self.ready.get() {
            if let Some(http) = ready.as_endpoint() {
                // Read afresh each time: a refused remote restored to the
                // vault's model and settings is admitted on the worker's next
                // try, and one restarted with another profile gets its floors.
                // The answers' pins go in with the vault's side, before
                // queries are let through.
                let admitted = http.served().and_then(|served| {
                    http.admit_with(served, |served| {
                        self.admit_holding_rung(
                            Admission {
                                transform: served.transform(),
                                evidence: served.evidence(&self.config),
                            },
                            admit,
                        )
                    })
                });
                match admitted {
                    Ok(()) => self.admitted.store(true, Ordering::Release),
                    Err(error) => {
                        self.admitted.store(false, Ordering::Release);
                        return Err(error);
                    }
                }
            }
            return Ok(Arc::clone(ready));
        }
        let local = local::LocalEmbedder::load(&self.config, &self.models)?;
        self.admit_holding_rung(
            Admission {
                transform: Some(local.transform()),
                evidence: evidence_floors(&self.config),
            },
            admit,
        )?;
        self.admitted.store(true, Ordering::Release);
        let embedder = local as Arc<dyn QueryEmbedder>;
        if self.ready.set(Arc::clone(&embedder)).is_ok()
            && let Some(loaded) = embedder.loaded()
        {
            tracing::info!(
                repo = %loaded.repo,
                revision = %loaded.revision,
                dimensions = loaded.dimensions,
                device = loaded.device,
                quant = loaded.quant,
                artifacts = loaded.artifacts,
                "embedder model loaded and admitted; dense recall is ready"
            );
        }
        // `set` loses a race; the winner is the one every caller must see.
        Ok(self.ready.get().map_or(embedder, Arc::clone))
    }

    /// Runs `admit`, and once the vault has taken `admission` holds a remote
    /// rung's answers to it, with no rung answer checked in between.
    fn admit_holding_rung(
        &self,
        admission: Admission<'_>,
        admit: impl FnOnce(Admission<'_>) -> oneiron::Result<()>,
    ) -> oneiron::Result<()> {
        let mut hold = self
            .rung_hold
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let taken = remote::RungHold {
            transform: admission.transform.map(str::to_owned),
            measured: admission.evidence != VectorEvidenceFloors::default(),
        };
        admit(admission)?;
        *hold = taken;
        Ok(())
    }

    /// The section's remote rung, if it configures one, held to the vault's
    /// model and to the space the vault admits from the provider
    /// ([`Self::ensure_ready`]). Its batches' run rows go to `receipts`.
    pub(crate) fn remote_rung(
        &self,
        receipts: Arc<dyn oneiron::llm::run_admission::RunReceiptSink>,
    ) -> oneiron::Result<Option<oneiron::embed::RemoteRung>> {
        build_remote_rung(&self.config, Arc::clone(&self.rung_hold), receipts)
    }

    /// Embeds a query, or says why it cannot.
    pub(crate) fn embed_query(&self, text: &str) -> Result<Vec<f32>, EmbedQueryRefusal> {
        let Some(embedder) = self.ready.get() else {
            return Err(EmbedQueryRefusal::NotReady);
        };
        if !self.admitted.load(Ordering::Acquire) {
            return Err(EmbedQueryRefusal::NotReady);
        }
        embedder.embed_query(text).map_err(|error| {
            tracing::warn!(kind = ?error.kind(), "query embedding failed");
            EmbedQueryRefusal::Failed
        })
    }
}

/// The embedding-transform descriptor a vault pins for this section, when it
/// is known before the provider loads.
///
/// Only the local provider declares one: read from the model's files when
/// they are on this host, complete and verified, and from the loaded model
/// otherwise ([`EmbedderSlot::ensure_ready`]).
///
/// An endpoint declares none before it is asked: a vault moves between the
/// local provider and an endpoint serving the same `model_id` without a
/// reembed, and the descriptor the local provider pinned stays in the vault
/// for its return. `embedder serve` lists its descriptor, which the worker
/// admits like a local model's ([`EmbedderSlot::ensure_ready`]); any other
/// endpoint's `model_id` is the promise that it makes the same vectors — the
/// same document embedding function, not only the same weights — which
/// nothing on its wire can check. `none` pins nothing either.
pub(crate) fn declared_transform(config: &EmbedderConfig) -> Option<String> {
    match config.provider {
        EmbedderProvider::None | EmbedderProvider::Endpoint => None,
        EmbedderProvider::Local => local::transform_on_disk(config),
    }
}

/// Where vector evidence starts in this section's embedding space, as far as
/// the section says before its provider is admitted: the measured floors of a
/// shipped local model run as it was measured, otherwise the engine's
/// default. An endpoint's depend on what its server serves, and are set when
/// the vault admits it ([`EmbedderSlot::ensure_ready`]).
pub(crate) fn evidence_floors(config: &EmbedderConfig) -> VectorEvidenceFloors {
    match config.provider {
        EmbedderProvider::Local => local::evidence::pinned_evidence(config).unwrap_or_default(),
        EmbedderProvider::Endpoint | EmbedderProvider::None => VectorEvidenceFloors::default(),
    }
}

/// The descriptor a vault moves to under this section, resolved now: the
/// local provider's from its model's verified metadata, fetching those small
/// files when they are not on this host (never the weights); an endpoint's
/// from its `/models` listing, which only `embedder serve` fills; `None` for
/// any other endpoint and for `none`, which declare none.
///
/// An error means the local model's metadata could not be fetched, verified
/// or read, or the endpoint's listing did not answer, and the transform the
/// section makes is unknown.
pub(crate) fn resolve_transform(config: &EmbedderConfig) -> oneiron::Result<Option<String>> {
    match config.provider {
        EmbedderProvider::None => Ok(None),
        EmbedderProvider::Endpoint => endpoint::resolve_transform(config),
        EmbedderProvider::Local => local::resolve_transform(config).map(Some),
    }
}

/// Maps a configured endpoint locality onto the engine's enum.
fn engine_locality(config: crate::config::EmbedderLocality) -> EmbedderLocality {
    match config {
        crate::config::EmbedderLocality::OnDevice => EmbedderLocality::OnDevice,
        crate::config::EmbedderLocality::OwnerServer => EmbedderLocality::OwnerServer,
        crate::config::EmbedderLocality::ThirdParty => EmbedderLocality::ThirdParty,
    }
}

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
    let Some(config) = config else {
        return Ok(None);
    };
    let Some(slot) = EmbedderSlot::from_config(config)? else {
        tracing::info!("embedder provider is none; the vault serves at rung 0");
        return Ok(None);
    };
    if let Some(ready) = slot.ready()
        && let Some(http) = ready.as_endpoint()
    {
        admitted::pay_primary(http, config, Arc::clone(&receipts))?;
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
        let http = endpoint::HttpEmbedder::from_config(&remote.endpoint_config(config))?;
        http.pay_through(Arc::new(admitted::AdmittedRequests::unmetered(
            remote,
            oneiron::embed::Embedder::locality(&*http),
            receipts,
        )?));
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

/// Sends the endpoint provider's document batches through leases on the
/// serve host's GPU pool; queries stay on the configured endpoint. Any other
/// provider computes on this host and takes none.
pub(crate) fn route_batches_through(
    slot: &EmbedderSlot,
    pool: crate::runtime::GpuPool,
    scope: Option<oneiron::federation::derivation::DerivationScope>,
) -> anyhow::Result<()> {
    let Some(http) = slot.ready().and_then(|ready| ready.as_endpoint()) else {
        tracing::warn!("[gpu] is set, but only an endpoint embedder routes batches through it");
        return Ok(());
    };
    let timeout = std::time::Duration::from_millis(slot.config().endpoint.timeout_ms);
    http.route_batches_through(pool, scope, timeout)?;
    Ok(())
}

#[cfg(test)]
mod tests;
