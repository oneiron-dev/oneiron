//! The server's half of a kind slot version move (OF-370; ARCH-0004
//! `#swap-check-ruling`, `#swap-check-not-worse`). The media backfill fills an
//! open move's candidate beside the spaces the slots bind; once a pass finds
//! nothing left to embed there, the vault's probes run paired on both spaces
//! ([`oneiron::Vault::check_space_move`]): each probe query goes through the
//! incumbent's tower twice, for its retest noise, and through the candidate's
//! once. The engine swaps the candidate in, keeps the incumbent, or leaves the
//! move open, and leaves the result note.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex, PoisonError, TryLockError};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use oneiron::embed::{
    EmbedderLocality, InputKind, MediaEmbedReport, MediaEmbedder, MediaEmbeddingInput, SpaceMove,
    SpaceMoveOutcome, SpaceMoveState, SpaceProbeAuthor, SpaceProbeEncoder, SpaceRef,
};
use oneiron::llm::manifest::ModelRole;
use oneiron::llm::media::{AiOperation, MediaPart, MediaRequest};
use oneiron::llm::{HostInferenceBinding, HostInferenceContext};
use oneiron::{
    BudgetExhaustionPolicy, CallClass, CallEnvelope, CallPurpose, ContentPart, Error, ImageContent,
    LlmMessage, LlmMessageRole, LlmRequest, ModelId, ModelLocality, ModelTierRef, ResponseFormat,
    TierPrecedence,
};

use super::core::SyncServer;
use super::media_embedding::{MediaEmbedRefusal, RuntimeMediaEmbedder};
use crate::ai_host::CHAT_ROLE;

/// How long an undecided move waits before its probes run again.
const SPACE_MOVE_RECHECK: Duration = Duration::from_secs(6 * 60 * 60);
/// The media type a probe query is sent as.
const PROBE_MEDIA_TYPE: &str = "text/plain; charset=utf-8";

/// Probes one pass writes per kind while a move is open.
const PROBE_AUTHOR_BATCH: usize = 4;
/// The most of a text document a probe author reads.
const PROBE_SOURCE_MAX_CHARS: usize = 4000;
/// The purpose a probe call is budgeted and audited under.
const PROBE_PURPOSE: &str = "embedding.space_probe";
/// What a probe author is asked.
const PROBE_INSTRUCTION: &str = "You write search queries for a retrieval check. Given one \
    stored item, write one short query, at most twenty words, that a person would type to find \
    it again later. Use your own words: describe it, never copy its phrases. Answer with the \
    query alone.";

/// Each move's check lock, by candidate: one check of a move runs at a time
/// in this process. A caller that finds one running waits for it and answers
/// with the reading it left, so a door's check that outlived its answer and
/// the backfill's own never pay the probes twice.
static MOVE_CHECKS: Mutex<BTreeMap<String, Arc<Mutex<()>>>> = Mutex::new(BTreeMap::new());

/// The kinds whose probes last failed to be written, so a refused or failing
/// author warns once and its recovery shows once, not every pass.
static PROBE_AUTHORS_FAILING: Mutex<BTreeSet<InputKind>> = Mutex::new(BTreeSet::new());

/// Records whether `kind`'s probe author is failing; true when that changed.
fn probe_author_failing(kind: InputKind, failing: bool) -> bool {
    let mut kinds = PROBE_AUTHORS_FAILING
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    if failing {
        kinds.insert(kind)
    } else {
        kinds.remove(&kind)
    }
}

/// One media backfill pass's result per space.
pub(super) type SpacePasses = Vec<(String, Result<MediaEmbedReport, MediaEmbedRefusal>)>;

/// The query towers a move's probes go through: the server's own text
/// embedder for the vault's text index, a declared space's `ai.embed` rung
/// otherwise.
struct ServerProbeEncoder<'a> {
    server: &'a SyncServer,
    incumbent: Option<RuntimeMediaEmbedder>,
    candidate: RuntimeMediaEmbedder,
    runtime: &'a tokio::runtime::Handle,
}

impl SpaceProbeEncoder for ServerProbeEncoder<'_> {
    fn encode_probe(&self, space: &SpaceRef, query: &str) -> oneiron::Result<Vec<f32>> {
        let embedder = match space {
            SpaceRef::TextIndex => {
                return self.server.embed_query(query).map_err(|refusal| {
                    oneiron::Error::InvalidConfig(format!(
                        "the text index's embedder refused a probe query: {refusal:?}"
                    ))
                });
            }
            SpaceRef::Declared(id) if *id == self.candidate.space_id() => &self.candidate,
            SpaceRef::Declared(id) => self
                .incumbent
                .as_ref()
                .filter(|incumbent| incumbent.space_id() == id)
                .ok_or_else(|| {
                    oneiron::Error::InvalidConfig(format!(
                        "no probe tower is open for embedding space {id}"
                    ))
                })?,
        };
        Ok(self.runtime.block_on(embedder.embed_query(
            InputKind::Text,
            PROBE_MEDIA_TYPE,
            query.as_bytes().to_vec(),
        ))?)
    }
}

/// A probe author on one of the server's seats, a model other than the
/// spaces' own: the chat seat for a text document, the captioner or the
/// Local-vision seat for an image, and for an audio document the chat seat
/// again, from the transcript the media transcribe seat hears. Each call is
/// one admitted role call the Dreamer pays for, as a stewardship draft is;
/// a transcription runs on the media meter.
struct ServerProbeAuthor<'a> {
    server: &'a SyncServer,
    role: ModelRole,
    model: ModelId,
    author: String,
    locality: ModelLocality,
    /// The media transcribe seat an audio document goes to first, and where
    /// it runs.
    transcriber: Option<(ModelId, ModelLocality)>,
    runtime: &'a tokio::runtime::Handle,
}

/// A probe author's id for `model`.
fn author_label(model: &ModelId) -> String {
    format!("{}/{}@{}", model.provider(), model.name(), model.revision())
}

impl ServerProbeAuthor<'_> {
    /// `document`'s transcript from the media transcribe seat, admitted by
    /// the vault's inference policy as an `ai.transcribe` call is; `None`
    /// when it hears no words.
    fn transcribe(&self, document: &MediaEmbeddingInput<'_>) -> oneiron::Result<Option<String>> {
        let Some((model, locality)) = &self.transcriber else {
            return Ok(None);
        };
        let purpose = CallPurpose::Other {
            name: PROBE_PURPOSE.to_owned(),
        };
        let mut request = MediaRequest {
            model: model.clone(),
            envelope: CallEnvelope {
                seat_effort: None,
                scope: Default::default(),
                tier: TierPrecedence::for_purpose(&purpose, ModelTierRef(PROBE_PURPOSE.to_owned())),
                purpose,
                class: CallClass::BestEffort,
                response_format: ResponseFormat::Text,
                locality: *locality,
            },
            operation: AiOperation::Transcribe,
            parts: vec![MediaPart::Audio {
                media_type: document.media_type.to_owned(),
                bytes: document.bytes.to_vec(),
            }],
            references: Vec::new(),
            params: BTreeMap::new(),
            voice: None,
        };
        let context = HostInferenceContext {
            binding: HostInferenceBinding::Advertised {
                model: model.clone(),
                locality: *locality,
            },
            extraction_egress: self.server.extraction_egress.as_deref(),
        };
        request.envelope = self
            .server
            .vault
            .authorize_raw_inference(request.admission_request(), &context)?
            .into_request()
            .envelope;
        // A transcription vouches for no world.
        request.envelope.scope.world = None;
        // The owner's space move, which no room launched, bills the owner.
        let response = self
            .runtime
            .block_on(self.server.ai.model_runtime().media().run(request, None))
            .map_err(|error| {
                Error::InvalidConfig(format!("space probe transcription failed: {error}"))
            })?;
        let transcript = response
            .parts
            .iter()
            .filter_map(|part| match part {
                MediaPart::Text { text } => Some(text.trim()),
                _ => None,
            })
            .filter(|text| !text.is_empty())
            .collect::<Vec<_>>()
            .join("\n");
        Ok(Some(transcript).filter(|transcript| !transcript.is_empty()))
    }
}

impl SpaceProbeAuthor for ServerProbeAuthor<'_> {
    fn author_id(&self) -> &str {
        &self.author
    }

    /// An audio document's bytes go to the transcriber alone: the chat seat
    /// reads its transcript, a text its admitted call carries where the
    /// vault's inference policy lets it, as it does a text document.
    fn locality(&self) -> EmbedderLocality {
        let locality = self
            .transcriber
            .as_ref()
            .map_or(self.locality, |(_, locality)| *locality);
        match locality {
            ModelLocality::OnDevice => EmbedderLocality::OnDevice,
            ModelLocality::OwnServer => EmbedderLocality::OwnerServer,
            ModelLocality::ThirdParty => EmbedderLocality::ThirdParty,
        }
    }

    fn write_probe(&self, document: &MediaEmbeddingInput<'_>) -> oneiron::Result<Option<String>> {
        let part = match document.kind {
            InputKind::Text => ContentPart::Text {
                text: std::str::from_utf8(document.bytes)
                    .map_err(|_| Error::InvalidConfig("a text document is not UTF-8".into()))?
                    .chars()
                    .take(PROBE_SOURCE_MAX_CHARS)
                    .collect(),
            },
            InputKind::Image => ContentPart::Image {
                media_type: document.media_type.to_owned(),
                image: ImageContent::Base64 {
                    data: base64::engine::general_purpose::STANDARD.encode(document.bytes),
                },
            },
            InputKind::Audio => match self.transcribe(document)? {
                Some(transcript) => ContentPart::Text {
                    text: transcript.chars().take(PROBE_SOURCE_MAX_CHARS).collect(),
                },
                None => return Ok(None),
            },
        };
        let purpose = CallPurpose::Other {
            name: PROBE_PURPOSE.to_owned(),
        };
        let request = LlmRequest {
            model: self.model.clone(),
            envelope: CallEnvelope {
                seat_effort: None,
                scope: Default::default(),
                tier: TierPrecedence::for_purpose(&purpose, ModelTierRef(PROBE_PURPOSE.to_owned())),
                purpose,
                class: CallClass::BestEffort,
                response_format: ResponseFormat::Text,
                locality: self.locality,
            },
            messages: vec![
                LlmMessage {
                    role: LlmMessageRole::System,
                    content: vec![ContentPart::Text {
                        text: PROBE_INSTRUCTION.to_owned(),
                    }],
                },
                LlmMessage {
                    role: LlmMessageRole::User,
                    content: vec![part],
                },
            ],
            tools: Vec::new(),
            params: BTreeMap::new(),
            provider_options: BTreeMap::new(),
        };
        let vault = &self.server.vault;
        let call = self
            .server
            .ai
            .admit_role(vault, self.role, request)
            .map_err(|refusal| {
                Error::InvalidConfig(format!("space probe call refused: {refusal}"))
            })?;
        let run_id = format!("space-probe:{}", document.entity_id.to_hex());
        let units = self.server.ai.chat_settings().turn_budget_units;
        let guard = vault.policy_budget_guard(
            run_id.clone(),
            units,
            oneiron::llm::DEFAULT_BUDGET_RESERVE_UNITS.min(units),
            BudgetExhaustionPolicy::Suspend,
            vault.dreamer_authority()?,
        )?;
        let run = self.server.ai.undeclared_run(run_id, guard);
        let response = self
            .runtime
            .block_on(call.ladder.generate(&run, call.request, None))
            .map_err(|error| Error::InvalidConfig(format!("space probe call failed: {error}")))?;
        let text: String = response
            .message
            .content
            .iter()
            .filter_map(|part| match part {
                ContentPart::Text { text } => Some(text.as_str()),
                _ => None,
            })
            .collect();
        Ok(text
            .lines()
            .map(|line| line.trim().trim_matches(|c| c == '"' || c == '\''))
            .find(|line| !line.is_empty())
            .map(str::to_owned))
    }
}

impl SyncServer {
    /// The seat that writes `kind`'s probes; none when no such seat is
    /// bound, or, for audio, no media transcribe seat.
    fn probe_author<'a>(
        &'a self,
        kind: InputKind,
        runtime: &'a tokio::runtime::Handle,
    ) -> Option<ServerProbeAuthor<'a>> {
        let (roles, transcriber): (&[ModelRole], _) = match kind {
            InputKind::Text => (&[CHAT_ROLE], None),
            InputKind::Image => (&[ModelRole::Captioner, ModelRole::LocalVision], None),
            InputKind::Audio => (
                &[CHAT_ROLE],
                Some(
                    self.ai
                        .model_runtime()
                        .media()
                        .seat(AiOperation::Transcribe)?,
                ),
            ),
        };
        roles.iter().find_map(|role| {
            let seat = self.ai.seat(*role)?;
            let author = match &transcriber {
                Some((heard, _)) => format!(
                    "{} from {}'s transcript",
                    author_label(&seat.model),
                    author_label(heard)
                ),
                None => author_label(&seat.model),
            };
            Some(ServerProbeAuthor {
                server: self,
                role: *role,
                author,
                model: seat.model.clone(),
                locality: seat.locality,
                transcriber: transcriber.clone(),
                runtime,
            })
        })
    }

    /// Tops up the probes of every kind an open move carries, a few per pass,
    /// while its candidate fills. Blocking.
    pub(super) fn author_space_probes(
        &self,
        runtime: &tokio::runtime::Handle,
        moves: &[SpaceMove],
    ) {
        let kinds: std::collections::BTreeSet<InputKind> = moves
            .iter()
            .filter(|moving| moving.state == SpaceMoveState::Open)
            .flat_map(|moving| moving.kinds.iter().copied())
            .collect();
        for kind in kinds {
            let Some(author) = self.probe_author(kind, runtime) else {
                if probe_author_failing(kind, true) {
                    tracing::warn!(
                        ?kind,
                        "an open embedding space move has no seat to write this kind's probes (text: the chat seat; image: a captioner or local-vision seat; audio: the chat seat and a media transcribe seat), so it stays undecided"
                    );
                }
                continue;
            };
            match self
                .vault
                .author_space_probes(kind, &author, PROBE_AUTHOR_BATCH)
            {
                Ok(report) => {
                    if probe_author_failing(kind, false) {
                        tracing::info!(?kind, "space probes are written again");
                    }
                    if report.written > 0 {
                        tracing::info!(
                            ?kind,
                            written = report.written,
                            held = report.held,
                            "space probes written"
                        );
                    }
                }
                Err(error) => {
                    if probe_author_failing(kind, true) {
                        tracing::warn!(
                            ?kind,
                            %error,
                            "space probes not written; an open embedding space move stays undecided until they are"
                        );
                    }
                }
            }
        }
    }

    /// Runs the paired probes of every open move whose candidate's pass just
    /// stored nothing, once it has never run or [`SPACE_MOVE_RECHECK`] has
    /// passed since. A check that fails takes the candidate's place in
    /// `passes`, so the backfill logs it once and backs off. Blocking.
    pub(super) fn check_space_moves(
        &self,
        runtime: &tokio::runtime::Handle,
        moves: &[SpaceMove],
        passes: &mut SpacePasses,
    ) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |since| since.as_secs());
        for moving in moves
            .iter()
            .filter(|moving| moving.state == SpaceMoveState::Open)
        {
            let Some(pass) = passes
                .iter_mut()
                .find(|(space, _)| *space == moving.candidate)
                .map(|(_, pass)| pass)
            else {
                continue;
            };
            if !matches!(pass, Ok(report) if report.embedded == 0) {
                continue;
            }
            if moving.last_check.as_ref().is_some_and(|check| {
                now.saturating_sub(check.checked_at) < SPACE_MOVE_RECHECK.as_secs()
            }) {
                continue;
            }
            match self.check_space_move(runtime, moving) {
                Ok(SpaceMoveOutcome::Filling) => {}
                Ok(SpaceMoveOutcome::SwappedIn(check)) => tracing::info!(
                    candidate = %moving.candidate,
                    incumbent = %moving.incumbent,
                    verdict = ?check.verdict,
                    "embedding space move swapped in: not worse on the vault's probes"
                ),
                Ok(SpaceMoveOutcome::Kept(check)) => tracing::info!(
                    candidate = %moving.candidate,
                    incumbent = %moving.incumbent,
                    verdict = ?check.verdict,
                    "embedding space move kept the incumbent: the candidate scored worse"
                ),
                Ok(SpaceMoveOutcome::Undecided(check)) => tracing::info!(
                    candidate = %moving.candidate,
                    incumbent = %moving.incumbent,
                    verdict = ?check.verdict,
                    "embedding space move undecided: the incumbent keeps serving"
                ),
                Err(refusal) => *pass = Err(refusal),
            }
        }
    }

    /// Runs one open move's paired probes now, through both spaces' towers.
    /// When a check of the move is already running, waits for it and answers
    /// with its reading instead ([`MOVE_CHECKS`]). Blocking.
    pub(crate) fn check_space_move(
        &self,
        runtime: &tokio::runtime::Handle,
        moving: &SpaceMove,
    ) -> Result<SpaceMoveOutcome, MediaEmbedRefusal> {
        let lock = Arc::clone(
            MOVE_CHECKS
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .entry(moving.candidate.clone())
                .or_default(),
        );
        let _checking = match lock.try_lock() {
            Ok(held) => held,
            Err(TryLockError::Poisoned(poisoned)) => poisoned.into_inner(),
            Err(TryLockError::WouldBlock) => {
                drop(lock.lock().unwrap_or_else(PoisonError::into_inner));
                return self.checked_move_outcome(moving);
            }
        };
        let candidate = self
            .media_embedder(&moving.candidate)?
            .on_runtime(runtime.clone());
        let incumbent = match &moving.incumbent {
            SpaceRef::TextIndex => None,
            SpaceRef::Declared(id) => Some(self.media_embedder(id)?.on_runtime(runtime.clone())),
        };
        let encoder = ServerProbeEncoder {
            server: self,
            incumbent,
            candidate,
            runtime,
        };
        Ok(self.vault.check_space_move(&moving.candidate, &encoder)?)
    }

    /// The reading the check that just finished left on `moving`, for a
    /// caller that waited on it: the move's close, a check newer than the one
    /// the caller read, or, with neither, a candidate still filling.
    fn checked_move_outcome(
        &self,
        moving: &SpaceMove,
    ) -> Result<SpaceMoveOutcome, MediaEmbedRefusal> {
        let now = self
            .vault
            .space_moves()?
            .into_iter()
            .find(|now| now.candidate == moving.candidate)
            .ok_or_else(|| {
                Error::InvalidConfig(format!("embedding space move {} is gone", moving.candidate))
            })?;
        let fresh = now
            .last_check
            .filter(|check| Some(check) != moving.last_check.as_ref());
        Ok(match (now.state, fresh) {
            (SpaceMoveState::SwappedIn { .. }, Some(check)) => SpaceMoveOutcome::SwappedIn(check),
            (SpaceMoveState::Kept { .. }, Some(check)) => SpaceMoveOutcome::Kept(check),
            (SpaceMoveState::Open, Some(check)) => SpaceMoveOutcome::Undecided(check),
            (SpaceMoveState::Open, None) => SpaceMoveOutcome::Filling,
            (_, _) => {
                return Err(Error::InvalidConfig(format!(
                    "embedding space move {} closed while its check ran",
                    moving.candidate
                ))
                .into());
            }
        })
    }
}
