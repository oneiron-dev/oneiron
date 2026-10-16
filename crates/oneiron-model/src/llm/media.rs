//! The `ai.*` call family past text (runtime "The ai.* call family"): image,
//! video, speech, transcription and embedding calls in one request shape,
//! admitted, sent and settled on the same run admission as a text call. The
//! requested operation picks the call, a row's input and output modalities
//! filter the seats that may serve it, and the answer is a list of parts.
//!
//! A media call is admitted as the [`LlmRequest`] its
//! [`MediaRequest::admission_request`] names: the same model, envelope and
//! params, no messages. So a run's teachers, offer, locality and route rules
//! hold for it unchanged, and one permit buys one physical call. Its usage
//! settles in token units: a provider that counts tokens is charged them,
//! one that counts images, seconds or characters is charged its row's
//! [`NativeRate`] for them.
use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

use super::image::{ImageBackend, ImageBytes, ImageIntent, ImageResponse};
use super::{BudgetLease, CallEnvelope, FatalLlmError, LlmError, LlmRequest, LlmResult, ModelId};

pub mod wav;

/// One call of the `ai.*` family, by the output it asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AiOperation {
    /// `ai.text`: text out, through the text seats' ladders.
    Text,
    /// `ai.image`: one image out; reference images make it an edit.
    Image,
    /// `ai.video`: a clip out, as a job the caller polls.
    Video,
    /// `ai.speech`: speech audio out of text.
    Speech,
    /// `ai.transcribe`: text out of speech audio.
    Transcribe,
    /// `ai.embed`: one vector per input text.
    Embed,
}

impl AiOperation {
    /// Every operation a media seat serves: all but text, which the role
    /// seats serve.
    pub const MEDIA: [Self; 5] = [
        Self::Image,
        Self::Video,
        Self::Speech,
        Self::Transcribe,
        Self::Embed,
    ];

    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Text => "text",
            Self::Image => "image",
            Self::Video => "video",
            Self::Speech => "speech",
            Self::Transcribe => "transcribe",
            Self::Embed => "embed",
        }
    }

    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        [Self::Text]
            .into_iter()
            .chain(Self::MEDIA)
            .find(|operation| operation.as_str() == name)
    }

    /// What the call puts out.
    #[must_use]
    pub fn output(self) -> Modality {
        match self {
            Self::Text | Self::Transcribe => Modality::Text,
            Self::Image => Modality::Image,
            Self::Video => Modality::Video,
            Self::Speech => Modality::Audio,
            Self::Embed => Modality::Embedding,
        }
    }

    /// What a call of this operation takes in when its row says nothing
    /// else.
    #[must_use]
    pub fn default_inputs(self) -> BTreeSet<Modality> {
        match self {
            Self::Text | Self::Speech | Self::Embed | Self::Video => [Modality::Text].into(),
            Self::Image => [Modality::Text, Modality::Image].into(),
            Self::Transcribe => [Modality::Audio].into(),
        }
    }

    /// The unit a provider counts this operation's work in, when it counts
    /// no tokens.
    #[must_use]
    pub fn native_unit(self) -> NativeUnit {
        match self {
            Self::Text | Self::Embed => NativeUnit::Token,
            Self::Image => NativeUnit::Image,
            Self::Video => NativeUnit::VideoSecond,
            Self::Speech => NativeUnit::Character,
            Self::Transcribe => NativeUnit::AudioSecond,
        }
    }

    /// Whether the call runs as a provider job that is submitted, polled and
    /// fetched, rather than answered on its request.
    #[must_use]
    pub fn is_job(self) -> bool {
        matches!(self, Self::Video)
    }
}

/// A kind of content a call takes in or puts out.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Modality {
    Text,
    Image,
    Audio,
    Video,
    Embedding,
}

impl Modality {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Text => "text",
            Self::Image => "image",
            Self::Audio => "audio",
            Self::Video => "video",
            Self::Embedding => "embedding",
        }
    }
}

/// A unit a provider counts media work in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeUnit {
    Token,
    Image,
    AudioSecond,
    VideoSecond,
    Character,
}

/// What `per` native units cost in token units, rounded up: the rate a run
/// settles a provider's native count at.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeRate {
    pub unit: NativeUnit,
    pub per: u64,
    pub tokens: u64,
}

impl NativeRate {
    /// The rate an operation settles at when its row names none: a generated
    /// image as a long answer, a second of audio or video as the tokens a
    /// model spends on it, four characters of speech as one token.
    #[must_use]
    pub fn default_for(operation: AiOperation) -> Self {
        let unit = operation.native_unit();
        let (per, tokens) = match unit {
            NativeUnit::Token => (1, 1),
            NativeUnit::Image => (1, 4_000),
            NativeUnit::AudioSecond => (1, 50),
            NativeUnit::VideoSecond => (1, 10_000),
            NativeUnit::Character => (4, 1),
        };
        Self { unit, per, tokens }
    }

    fn charge(&self, count: u64) -> u64 {
        let per = u128::from(self.per.max(1));
        let units = (u128::from(count) * u128::from(self.tokens)).div_ceil(per);
        u64::try_from(units).unwrap_or(u64::MAX)
    }
}

/// What one model row serves past text: its operations, the modalities its
/// calls take in and put out, and the rates its native counts settle at.
/// A catalog row carries it under its `media` metadata
/// ([`super::LlmCatalogEntry::media`]).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MediaCaps {
    pub operations: BTreeSet<AiOperation>,
    pub inputs: BTreeSet<Modality>,
    pub outputs: BTreeSet<Modality>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub native_rates: Vec<NativeRate>,
    /// The most reference images one call may carry; 0 takes none.
    #[serde(default)]
    pub max_references: usize,
}

impl MediaCaps {
    /// A row that serves `operation` with its default inputs and rate.
    #[must_use]
    pub fn for_operation(operation: AiOperation) -> Self {
        Self {
            operations: [operation].into(),
            inputs: operation.default_inputs(),
            outputs: [operation.output()].into(),
            native_rates: vec![NativeRate::default_for(operation)],
            max_references: if operation == AiOperation::Image {
                8
            } else {
                0
            },
        }
    }

    /// Whether a call that asks for `operation` over `inputs` fits this row.
    #[must_use]
    pub fn serves(&self, operation: AiOperation, inputs: &BTreeSet<Modality>) -> bool {
        self.operations.contains(&operation)
            && self.outputs.contains(&operation.output())
            && inputs.is_subset(&self.inputs)
    }

    /// The rate `unit` settles at on this row, its operation's default when
    /// it names none.
    #[must_use]
    pub fn rate(&self, operation: AiOperation, unit: NativeUnit) -> NativeRate {
        self.native_rates
            .iter()
            .find(|rate| rate.unit == unit)
            .copied()
            .unwrap_or_else(|| {
                let default = NativeRate::default_for(operation);
                if default.unit == unit {
                    default
                } else {
                    NativeRate {
                        unit,
                        per: 1,
                        tokens: 1,
                    }
                }
            })
    }
}

/// One part of a media call's input or answer. Bytes stay bytes here; a
/// host's wire encodes them.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum MediaPart {
    Text {
        text: String,
    },
    Image {
        media_type: String,
        bytes: Vec<u8>,
    },
    Audio {
        media_type: String,
        bytes: Vec<u8>,
    },
    /// A clip's bytes, or where the provider keeps it when it hands back
    /// no bytes.
    Video {
        media_type: String,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        bytes: Vec<u8>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        uri: Option<String>,
    },
    Embedding {
        vector: Vec<f32>,
    },
}

impl MediaPart {
    #[must_use]
    pub fn modality(&self) -> Modality {
        match self {
            Self::Text { .. } => Modality::Text,
            Self::Image { .. } => Modality::Image,
            Self::Audio { .. } => Modality::Audio,
            Self::Video { .. } => Modality::Video,
            Self::Embedding { .. } => Modality::Embedding,
        }
    }

    /// The part as an image, when it is one with bytes.
    #[must_use]
    pub fn as_image(&self) -> Option<ImageBytes> {
        match self {
            Self::Image { media_type, bytes } if !bytes.is_empty() => Some(ImageBytes {
                bytes: bytes.clone(),
                media_type: media_type.clone(),
            }),
            _ => None,
        }
    }
}

/// One media call as a run admits it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MediaRequest {
    pub model: ModelId,
    pub envelope: CallEnvelope,
    pub operation: AiOperation,
    /// The inputs, in order: the instruction or the texts, the audio to
    /// transcribe.
    pub parts: Vec<MediaPart>,
    /// The images an image call edits, or a video call starts from, in
    /// order. Each one is a part the call sends.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub references: Vec<MediaPart>,
    /// Generic output params (`size`, `voice`, `seconds`, `dimensions`,
    /// ...). Never a route selector: the model id and the host's binding
    /// pick the model and its route, as for a text call.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub params: BTreeMap<String, JsonValue>,
    /// The voice a speech call renders in, typed: a provider's stock voice,
    /// or a banked identity's clone on this call's target. A call that
    /// names one names no `voice` param.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub voice: Option<MediaVoice>,
}

/// The voice of one speech call. A banked identity (ARCH-0061 §5, the
/// render-target law) lives in the vault's reference bank; a provider only
/// ever sees its target's recorded voice id for it, which the host resolved
/// from the bank for this call's rung.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum MediaVoice {
    /// The provider's own voice, by its name: no banked identity.
    Stock { name: String },
    /// A banked identity's clone on this call's target: the provider's
    /// disposable id for it.
    Clone { id: String },
}

impl MediaVoice {
    /// The name or id the provider's wire carries.
    #[must_use]
    pub fn wire_id(&self) -> &str {
        match self {
            Self::Stock { name } => name,
            Self::Clone { id } => id,
        }
    }
}

impl MediaRequest {
    /// The call as the run admits it: this model, envelope and params, and
    /// no messages. Admission reads only these.
    #[must_use]
    pub fn admission_request(&self) -> LlmRequest {
        LlmRequest {
            model: self.model.clone(),
            envelope: self.envelope.clone(),
            messages: Vec::new(),
            tools: Vec::new(),
            params: self.params.clone(),
            provider_options: BTreeMap::new(),
        }
    }

    /// Every modality the call sends.
    #[must_use]
    pub fn inputs(&self) -> BTreeSet<Modality> {
        self.parts
            .iter()
            .chain(&self.references)
            .map(MediaPart::modality)
            .collect()
    }

    /// The text parts, joined by blank lines: an image, video or speech
    /// call's instruction or script.
    #[must_use]
    pub fn text(&self) -> String {
        self.texts().collect::<Vec<_>>().join("\n\n")
    }

    /// Each text part, in order: an embedding call's inputs.
    pub fn texts(&self) -> impl Iterator<Item = &str> {
        self.parts.iter().filter_map(|part| match part {
            MediaPart::Text { text } => Some(text.as_str()),
            _ => None,
        })
    }

    /// The reference images, each with bytes; `None` when one has none or
    /// is not an image.
    #[must_use]
    pub fn reference_images(&self) -> Option<Vec<ImageBytes>> {
        self.references.iter().map(MediaPart::as_image).collect()
    }

    /// The digest of the call's canonical bytes: what its dispatch receipt
    /// names.
    pub fn canonical_hash_hex(&self) -> Result<String, serde_json::Error> {
        let bytes = super::canonical_json_bytes(self)?;
        Ok(oneiron_contracts::entity_id::bytes_to_hex_lower(
            blake3::hash(&bytes).as_bytes(),
        ))
    }

    /// The image call as an [`ImageIntent`]: its text the instruction, its
    /// `size` (`"WxH"`) or `width`/`height` params the size (1024x1024 by
    /// default), every other param as it came.
    pub fn image_intent(&self) -> LlmResult<ImageIntent> {
        let mut params = self.params.clone();
        let (mut width, mut height) = (1024, 1024);
        if let Some(size) = params.remove("size") {
            let (w, h) = size
                .as_str()
                .and_then(|size| size.split_once('x'))
                .and_then(|(w, h)| Some((w.parse::<u32>().ok()?, h.parse::<u32>().ok()?)))
                .ok_or(FatalLlmError::InvalidRequest)?;
            (width, height) = (w, h);
        }
        for (key, slot) in [("width", &mut width), ("height", &mut height)] {
            if let Some(value) = params.remove(key) {
                *slot = value
                    .as_u64()
                    .and_then(|value| u32::try_from(value).ok())
                    .ok_or(FatalLlmError::InvalidRequest)?;
            }
        }
        Ok(ImageIntent {
            model: self.model.clone(),
            instruction: self.text(),
            width,
            height,
            params,
        })
    }
}

/// What a provider counted for one media call. Tokens when it counts
/// tokens; otherwise its native counts.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct MediaUsage {
    #[serde(default)]
    pub input_tokens: u64,
    #[serde(default)]
    pub output_tokens: u64,
    #[serde(default)]
    pub images: u64,
    #[serde(default)]
    pub audio_ms: u64,
    #[serde(default)]
    pub video_ms: u64,
    #[serde(default)]
    pub characters: u64,
    #[serde(default, skip_serializing_if = "JsonValue::is_null")]
    pub raw_provider: JsonValue,
}

impl MediaUsage {
    /// The call's charge in token units: the tokens the provider counted,
    /// else each native count at `caps`' rate for it. `None` when it
    /// counted nothing, so the run charges the call's reservation.
    #[must_use]
    pub fn token_units(&self, operation: AiOperation, caps: &MediaCaps) -> Option<u64> {
        let tokens = self.input_tokens.saturating_add(self.output_tokens);
        if tokens > 0 {
            return Some(tokens);
        }
        let seconds = |ms: u64| ms.div_ceil(1_000);
        let native = [
            (NativeUnit::Image, self.images),
            (NativeUnit::AudioSecond, seconds(self.audio_ms)),
            (NativeUnit::VideoSecond, seconds(self.video_ms)),
            (NativeUnit::Character, self.characters),
        ];
        let units = native
            .into_iter()
            .filter(|(_, count)| *count > 0)
            .map(|(unit, count)| caps.rate(operation, unit).charge(count))
            .fold(0u64, u64::saturating_add);
        (units > 0).then_some(units)
    }
}

/// One media call's answer.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MediaResponse {
    pub parts: Vec<MediaPart>,
    pub usage: MediaUsage,
    pub model: ModelId,
}

impl MediaResponse {
    /// An image adapter's answer as parts: its image, counted as one.
    #[must_use]
    pub fn from_image(response: ImageResponse) -> Self {
        Self {
            parts: vec![MediaPart::Image {
                media_type: response.image.media_type,
                bytes: response.image.bytes,
            }],
            usage: MediaUsage {
                images: 1,
                raw_provider: JsonValue::Object(response.metadata.into_iter().collect()),
                ..MediaUsage::default()
            },
            model: response.model,
        }
    }

    /// The first image part.
    #[must_use]
    pub fn image(&self) -> Option<ImageBytes> {
        self.parts.iter().find_map(MediaPart::as_image)
    }
}

/// Where a submitted media job stands, as its provider says.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum MediaJobState {
    Queued,
    Running {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        progress: Option<u8>,
    },
    Done {
        response: MediaResponse,
    },
    Failed {
        error: LlmError,
    },
}

impl MediaJobState {
    /// Whether the job has ended, answered or not.
    #[must_use]
    pub fn ended(&self) -> bool {
        matches!(self, Self::Done { .. } | Self::Failed { .. })
    }
}

pub type MediaFuture<'a, T> = Pin<Box<dyn Future<Output = LlmResult<T>> + Send + 'a>>;

/// A provider adapter's media wire. Each call carries the lease of the
/// permit that bought it; a host-built transport sends one request per call,
/// so a run's media gate may wrap it. A job's poll and cancel ride the
/// permit its submit started.
pub trait MediaBackend: Send + Sync {
    /// Runs one call to its answer.
    fn run<'a>(
        &'a self,
        request: MediaRequest,
        lease: &'a BudgetLease,
    ) -> MediaFuture<'a, MediaResponse>;

    /// Starts one long call as a provider job; returns the provider's job id.
    fn submit<'a>(
        &'a self,
        _request: MediaRequest,
        _lease: &'a BudgetLease,
    ) -> MediaFuture<'a, String> {
        Box::pin(async { Err::<String, LlmError>(FatalLlmError::InvalidRequest.into()) })
    }

    /// Where the provider's job `job` for `model` stands; a done job's
    /// answer is fetched with it.
    fn poll<'a>(
        &'a self,
        _model: &'a ModelId,
        _job: &'a str,
        _lease: &'a BudgetLease,
    ) -> MediaFuture<'a, MediaJobState> {
        Box::pin(async { Err::<MediaJobState, LlmError>(FatalLlmError::InvalidRequest.into()) })
    }

    /// Asks the provider to stop job `job`.
    fn cancel<'a>(
        &'a self,
        _model: &'a ModelId,
        _job: &'a str,
        _lease: &'a BudgetLease,
    ) -> MediaFuture<'a, ()> {
        Box::pin(async { Err::<(), LlmError>(FatalLlmError::InvalidRequest.into()) })
    }
}

/// An [`ImageBackend`] as a media backend: an image call with reference
/// images is its reference edit, one without is a generation.
pub struct ImageMedia(pub Arc<dyn ImageBackend>);

impl MediaBackend for ImageMedia {
    fn run<'a>(
        &'a self,
        request: MediaRequest,
        lease: &'a BudgetLease,
    ) -> MediaFuture<'a, MediaResponse> {
        Box::pin(async move {
            if request.operation != AiOperation::Image {
                return Err(FatalLlmError::InvalidRequest.into());
            }
            let references = request
                .reference_images()
                .ok_or(FatalLlmError::InvalidRequest)?;
            let intent = request.image_intent()?;
            let response = if references.is_empty() {
                self.0.generate(intent, lease).await?
            } else {
                self.0.reference_edit(intent, references, lease).await?
            };
            Ok::<_, LlmError>(MediaResponse::from_image(response))
        })
    }
}

/// The host's door for one engine media call: it admits the call under its
/// run, sends it rung by rung and settles it. Engine code that makes a media
/// call holds this, never a backend or a bare lease.
pub trait AiMediaDoor: Send + Sync {
    fn call<'a>(&'a self, request: MediaRequest) -> MediaFuture<'a, MediaResponse>;
}
