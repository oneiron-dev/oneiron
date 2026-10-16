//! The media embedder (OF-370; ARCH-0036 `#media-embedder`): one adapter over
//! the `ai.embed` seat, the same admitted `run(Embed)` the `/v1/ai/embed` door
//! calls. A declared space names its model: its id is an `ai.embed` rung's id
//! (`provider/name@revision`, as `GET /v1/ai/options` lists it) and then
//! `@where`, so a space is one pinned rung and never a ladder that could
//! answer from two models. Each call is admitted by the vault's inference
//! policy for that rung, then sent and settled on the media meter; each
//! vector it answers must be one finite vector of the space's width.
//!
//! A context pack's media query awaits it on its own runtime
//! ([`RuntimeMediaEmbedder::embed_query`]). The backfill worker hands the
//! engine its synchronous [`MediaEmbedder`] door on a blocking thread, and
//! each call there is driven on the server's runtime; the engine refuses a
//! third-party rung for stored media.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;

use oneiron::embed::{
    EmbedderLocality, EmbeddingSpace, InputKind, MediaEmbedReport, MediaEmbedder,
    MediaEmbeddingInput,
};
use oneiron::llm::media::{AiOperation, MediaPart, MediaRequest, Modality};
use oneiron::{
    CallClass, CallEnvelope, CallPurpose, FatalLlmError, LlmError, ModelId, ModelLocality,
    ModelTierRef, ResponseFormat, TierPrecedence,
};

use super::core::SyncServer;
use crate::ai_host::AiHandle;

/// How long the backfill sleeps after a pass that stored nothing.
const BACKFILL_IDLE: Duration = Duration::from_secs(30);
/// Ceiling on the backfill's wait while a space keeps failing.
const BACKFILL_MAX_BACKOFF: Duration = Duration::from_secs(15 * 60);
/// ASSETs one backfill pass embeds per space.
const BACKFILL_BATCH: usize = 16;

/// Why a media embed was refused or failed.
#[derive(Debug, thiserror::Error)]
pub(crate) enum MediaEmbedRefusal {
    #[error("no [models.media.embed] seat serves on this server")]
    NoSeat,
    #[error("embedding space {0} is not declared")]
    Undeclared(String),
    #[error(
        "embedding space {0} names no ai.embed rung; its id is a rung id GET /v1/ai/options lists, then @where"
    )]
    Unmapped(String),
    #[error("embedding space {space} has no {kind:?} query tower")]
    NoTower { space: String, kind: InputKind },
    #[error("a text query's bytes are not UTF-8")]
    NotText,
    #[error("the ai.embed rung {model} takes no {modality:?} input")]
    NoInput { model: ModelId, modality: Modality },
    #[error("the vault's inference policy refuses the ai.embed call")]
    Denied(oneiron::Error),
    #[error("the ai.embed call failed: {0}")]
    Call(LlmError),
    #[error(
        "the ai.embed rung answered a {got}-wide vector for space {space}, which is {expected} wide"
    )]
    Width {
        space: String,
        expected: usize,
        got: usize,
    },
    #[error("the ai.embed rung answered no single finite vector")]
    Malformed,
    #[error(transparent)]
    Vault(#[from] oneiron::Error),
}

impl From<MediaEmbedRefusal> for oneiron::Error {
    fn from(refusal: MediaEmbedRefusal) -> Self {
        match refusal {
            MediaEmbedRefusal::Width { expected, got, .. } => {
                Self::DimensionMismatch { expected, got }
            }
            MediaEmbedRefusal::Denied(error) | MediaEmbedRefusal::Vault(error) => error,
            MediaEmbedRefusal::Call(error) => Self::UpstreamToolFailure {
                tool: "ai.embed",
                code: llm_code(&error).into(),
            },
            MediaEmbedRefusal::Malformed => Self::UpstreamToolFailure {
                tool: "ai.embed",
                code: "malformed_answer".into(),
            },
            other => Self::InvalidConfig(other.to_string()),
        }
    }
}

/// The caller-safe code an `ai.embed` failure reads as, as `/v1/ai/embed`
/// names it.
fn llm_code(error: &LlmError) -> &'static str {
    match error {
        LlmError::BudgetDenied(_) => "budget_denied",
        LlmError::Fatal(FatalLlmError::Auth) => "provider_auth",
        LlmError::Fatal(FatalLlmError::ContentFiltered) => "content_filtered",
        LlmError::Fatal(FatalLlmError::EmptyResponse) => "empty_response",
        LlmError::Fatal(_) => "invalid_request",
        LlmError::Retryable(_) => "provider_unavailable",
    }
}

/// One declared space's embedder: the `ai.embed` rung its id pins, on the
/// server's media runtime.
pub(crate) struct RuntimeMediaEmbedder {
    space: EmbeddingSpace,
    model: ModelId,
    locality: ModelLocality,
    inputs: BTreeSet<Modality>,
    ai: AiHandle,
    vault: Arc<oneiron::Vault>,
    egress: Option<Arc<dyn oneiron::llm::ExtractionEgressPredicate>>,
    /// The runtime the synchronous door drives its calls on; a blocking
    /// caller sets it.
    runtime: Option<tokio::runtime::Handle>,
}

impl SyncServer {
    /// The embedder for declared space `space_id`: the `ai.embed` rung its id
    /// names. Reads the vault's declared spaces.
    pub(crate) fn media_embedder(
        &self,
        space_id: &str,
    ) -> Result<RuntimeMediaEmbedder, MediaEmbedRefusal> {
        let media = self.ai.model_runtime().media();
        if media.seat(AiOperation::Embed).is_none() {
            return Err(MediaEmbedRefusal::NoSeat);
        }
        let space = self
            .vault
            .embedding_spaces()?
            .into_iter()
            .find(|space| space.id == space_id)
            .ok_or_else(|| MediaEmbedRefusal::Undeclared(space_id.to_owned()))?;
        let unmapped = || MediaEmbedRefusal::Unmapped(space.id.clone());
        let (pinned, _) = space.id.rsplit_once('@').ok_or_else(unmapped)?;
        let row = media
            .options(Some(AiOperation::Embed), &BTreeSet::new())
            .into_iter()
            .find(|row| row.model == pinned)
            .ok_or_else(unmapped)?;
        let model = ModelId::new(row.model).map_err(|_| unmapped())?;
        Ok(RuntimeMediaEmbedder {
            space,
            model,
            locality: row.locality,
            inputs: row.inputs,
            ai: self.ai.clone(),
            vault: Arc::clone(&self.vault),
            egress: self.extraction_egress.clone(),
            runtime: None,
        })
    }

    /// Starts the media backfill, or returns `None` when no `ai.embed` seat
    /// serves.
    pub(crate) fn spawn_media_embedding_worker(
        self: &Arc<Self>,
    ) -> Option<tokio::task::JoinHandle<()>> {
        self.ai.model_runtime().media().seat(AiOperation::Embed)?;
        let server = Arc::clone(self);
        Some(tokio::spawn(async move {
            server.backfill_media_forever().await
        }))
    }

    /// Fills every slot-bound space while passes store vectors, sleeps when
    /// one stores none, and backs off while a space fails. Each space's
    /// failure is logged once until it changes. A stable recovery of a
    /// provider that was down (OF-305) ends a backoff at once: the spaces
    /// that failed are tried again from the first wait.
    async fn backfill_media_forever(self: Arc<Self>) {
        let mut wait = BACKFILL_IDLE;
        let mut failing: BTreeMap<String, String> = BTreeMap::new();
        let mut recoveries = self.ai.model_runtime().recoveries();
        loop {
            let server = Arc::clone(&self);
            let runtime = tokio::runtime::Handle::current();
            let passes = tokio::task::spawn_blocking(move || server.backfill_media_pass(&runtime))
                .await
                .unwrap_or_else(|error| {
                    tracing::warn!(
                        panicked = error.is_panic(),
                        "media backfill task failed to join"
                    );
                    Vec::new()
                });
            let mut embedded = 0;
            let mut failed = false;
            for (space, pass) in passes {
                match pass {
                    Ok(report) => {
                        if failing.remove(&space).is_some() {
                            tracing::info!(%space, "media backfill fills the space again");
                        }
                        embedded += report.embedded;
                    }
                    Err(error) => {
                        failed = true;
                        let reason = error.to_string();
                        if failing.get(&space) != Some(&reason) {
                            tracing::warn!(%space, %reason, "media backfill cannot fill the space; it retries");
                            failing.insert(space, reason);
                        }
                    }
                }
            }
            if failed {
                wait = (wait * 2).min(BACKFILL_MAX_BACKOFF);
            } else {
                wait = BACKFILL_IDLE;
                if embedded > 0 {
                    continue;
                }
            }
            if failing.is_empty() {
                tokio::time::sleep(wait).await;
                continue;
            }
            tokio::select! {
                () = tokio::time::sleep(wait) => {}
                recovered = recoveries.changed() => {
                    if recovered.is_ok() {
                        tracing::info!("a provider recovered; media backfill tries its failing spaces again");
                        wait = BACKFILL_IDLE;
                    } else {
                        // The runtime is gone: no recovery comes, and the
                        // backoff runs out as before.
                        tokio::time::sleep(wait).await;
                    }
                }
            }
        }
    }

    /// One pass over each space a kind slot binds to, the text slot's on the
    /// one-space preset included, and each open version move's candidate;
    /// then the probe check of each candidate that is full
    /// ([`Self::check_space_moves`]). Blocking.
    fn backfill_media_pass(
        &self,
        runtime: &tokio::runtime::Handle,
    ) -> Vec<(String, Result<MediaEmbedReport, MediaEmbedRefusal>)> {
        let (bindings, moves) = match (self.vault.kind_slot_bindings(), self.vault.space_moves()) {
            (Ok(bindings), Ok(moves)) => (bindings, moves),
            (Err(error), _) | (_, Err(error)) => return vec![(String::new(), Err(error.into()))],
        };
        let mut spaces: BTreeSet<&str> = InputKind::ALL
            .into_iter()
            .filter_map(|kind| bindings.space_for(kind))
            .collect();
        spaces.extend(
            moves
                .iter()
                .filter(|moving| moving.state == oneiron::embed::SpaceMoveState::Open)
                .map(|moving| moving.candidate.as_str()),
        );
        let mut passes: Vec<_> = spaces
            .into_iter()
            .map(|space| {
                let pass = self.media_embedder(space).and_then(|embedder| {
                    let embedder = embedder.on_runtime(runtime.clone());
                    Ok(self
                        .vault
                        .reconcile_media_embeddings(&embedder, BACKFILL_BATCH)?)
                });
                (space.to_owned(), pass)
            })
            .collect();
        self.check_space_moves(runtime, &moves, &mut passes);
        passes
    }
}

impl RuntimeMediaEmbedder {
    /// This embedder with its synchronous door driven on `runtime`, from a
    /// thread that is not one of its workers.
    pub(crate) fn on_runtime(mut self, runtime: tokio::runtime::Handle) -> Self {
        self.runtime = Some(runtime);
        self
    }

    /// One query of `kind` into this space, through that kind's tower.
    pub(crate) async fn embed_query(
        &self,
        kind: InputKind,
        media_type: &str,
        bytes: Vec<u8>,
    ) -> Result<Vec<f32>, MediaEmbedRefusal> {
        if !self.space.query_towers.contains(&kind) {
            return Err(MediaEmbedRefusal::NoTower {
                space: self.space.id.clone(),
                kind,
            });
        }
        self.embed_one(media_part(kind, media_type, bytes)?).await
    }

    /// One part to its vector, as an `ai.embed` call: the vault's inference
    /// policy admits it for this rung, and the rung's ladder sends and
    /// settles it on the media meter.
    async fn embed_one(&self, part: MediaPart) -> Result<Vec<f32>, MediaEmbedRefusal> {
        let modality = part.modality();
        if !self.inputs.contains(&modality) {
            return Err(MediaEmbedRefusal::NoInput {
                model: self.model.clone(),
                modality,
            });
        }
        let request = self.admit(part)?;
        let response = self
            .ai
            .model_runtime()
            .media()
            .run(request)
            .await
            .map_err(MediaEmbedRefusal::Call)?;
        let mut vectors = response.parts.into_iter().filter_map(|part| match part {
            MediaPart::Embedding { vector } => Some(vector),
            _ => None,
        });
        let (Some(vector), None) = (vectors.next(), vectors.next()) else {
            return Err(MediaEmbedRefusal::Malformed);
        };
        if vector.len() != self.space.dimensions {
            return Err(MediaEmbedRefusal::Width {
                space: self.space.id.clone(),
                expected: self.space.dimensions,
                got: vector.len(),
            });
        }
        if vector.iter().any(|value| !value.is_finite()) {
            return Err(MediaEmbedRefusal::Malformed);
        }
        Ok(vector)
    }

    /// The call as `/v1/ai/embed` admits it: the vault's inference policy
    /// for this rung, and no world the call vouches for.
    fn admit(&self, part: MediaPart) -> Result<MediaRequest, MediaEmbedRefusal> {
        let purpose = CallPurpose::Other {
            name: format!("ai.{}", AiOperation::Embed.as_str()),
        };
        let mut request = MediaRequest {
            model: self.model.clone(),
            envelope: CallEnvelope {
                scope: Default::default(),
                tier: TierPrecedence::for_purpose(
                    &purpose,
                    ModelTierRef(format!("media-{}", AiOperation::Embed.as_str())),
                ),
                purpose,
                class: CallClass::BestEffort,
                response_format: ResponseFormat::Text,
                locality: self.locality,
                seat_effort: None,
            },
            operation: AiOperation::Embed,
            parts: vec![part],
            references: Vec::new(),
            params: BTreeMap::new(),
            voice: None,
        };
        let context = oneiron::llm::HostInferenceContext {
            binding: oneiron::llm::HostInferenceBinding::Advertised {
                model: self.model.clone(),
                locality: self.locality,
            },
            extraction_egress: self.egress.as_deref(),
        };
        let authorized = self
            .vault
            .authorize_raw_inference(request.admission_request(), &context)
            .map_err(MediaEmbedRefusal::Denied)?;
        request.envelope = authorized.into_request().envelope;
        request.envelope.scope.world = None;
        Ok(request)
    }
}

impl MediaEmbedder for RuntimeMediaEmbedder {
    fn space_id(&self) -> &str {
        &self.space.id
    }

    fn dimensions(&self) -> usize {
        self.space.dimensions
    }

    fn locality(&self) -> EmbedderLocality {
        match self.locality {
            ModelLocality::OnDevice => EmbedderLocality::OnDevice,
            ModelLocality::OwnServer => EmbedderLocality::OwnerServer,
            ModelLocality::ThirdParty => EmbedderLocality::ThirdParty,
        }
    }

    /// One call per input, each driven on the embedder's runtime from the
    /// blocking thread the engine calls on.
    fn embed_media(&self, inputs: &[MediaEmbeddingInput<'_>]) -> oneiron::Result<Vec<Vec<f32>>> {
        let runtime = self
            .runtime
            .as_ref()
            .ok_or(oneiron::Error::InvariantViolation(
                "a media embedder's synchronous door has no runtime to drive its calls on",
            ))?;
        inputs
            .iter()
            .map(|input| -> oneiron::Result<Vec<f32>> {
                let part = media_part(input.kind, input.media_type, input.bytes.to_vec())?;
                Ok(runtime.block_on(self.embed_one(part))?)
            })
            .collect()
    }
}

/// The part an input of `kind` sends.
fn media_part(
    kind: InputKind,
    media_type: &str,
    bytes: Vec<u8>,
) -> Result<MediaPart, MediaEmbedRefusal> {
    let media_type = media_type.to_owned();
    Ok(match kind {
        InputKind::Image => MediaPart::Image { media_type, bytes },
        InputKind::Audio => MediaPart::Audio { media_type, bytes },
        InputKind::Text => MediaPart::Text {
            text: String::from_utf8(bytes).map_err(|_| MediaEmbedRefusal::NotText)?,
        },
    })
}
