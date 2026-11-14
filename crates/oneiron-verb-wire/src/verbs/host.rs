//! Moved from `crates/oneiron/src/verbs/host.rs` (lib split W3: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use crate::memory::hook_regen_doors::PackPutOutcome;
pub use crate::receipt::questions::AI_VERDICT_DEADLINE_MS;
pub use crate::verbs::host::ask_image::*;
pub use crate::verbs::host::hooks_replay::*;
pub use crate::verbs::host::pack_setup::*;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use oneiron_contracts::memory::MemoryError;
use oneiron_contracts::memory::MemoryResult;
use oneiron_model::llm::media::MediaPart;
use oneiron_model::llm::media::MediaResponse;
use oneiron_model::llm::media::MediaUsage;
use oneiron_store::write_envelope::skill_source::HubFile;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;

/// One file of a pack folder, its content an explicit choice: text, stored as
/// its UTF-8 bytes, or any bytes (an image, a font, a Wasm module) as
/// standard base64. `vault.packs.put` and `POST /v1/owner/packs` both take it.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(untagged)]
pub enum PackFileInput {
    Text(PackTextFile),
    Bytes(PackBytesFile),
}

/// A pack file sent as text.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PackTextFile {
    /// Relative to the pack folder, `/`-separated.
    pub path: String,
    pub text: String,
}

/// A pack file sent as bytes.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PackBytesFile {
    /// Relative to the pack folder, `/`-separated.
    pub path: String,
    /// The file's bytes, RFC 4648 standard base64.
    pub content_base64: String,
}

/// A pack file whose `content_base64` does not decode.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("pack file {path}: content_base64 is not standard base64")]
pub struct PackFileDecodeError {
    pub path: String,
}

impl PackFileInput {
    /// The file as the pack source reads it, its content decoded.
    ///
    /// # Errors
    /// [`PackFileDecodeError`] when its base64 does not decode.
    pub fn into_hub_file(self) -> Result<HubFile, PackFileDecodeError> {
        match self {
            Self::Text(file) => Ok(HubFile::new(file.path, file.text.into_bytes())),
            Self::Bytes(file) => match STANDARD.decode(file.content_base64.as_bytes()) {
                Ok(bytes) => Ok(HubFile::new(file.path, bytes)),
                Err(_) => Err(PackFileDecodeError { path: file.path }),
            },
        }
    }
}

/// A pack folder's files as the pack source reads them, each decoded before
/// the install door sees any of them.
///
/// # Errors
/// [`PackFileDecodeError`] naming the first file whose base64 does not decode.
pub fn decode_pack_files(files: Vec<PackFileInput>) -> Result<Vec<HubFile>, PackFileDecodeError> {
    files
        .into_iter()
        .map(PackFileInput::into_hub_file)
        .collect()
}

/// `vault.packs.put`'s input: the pack folder's files. The put installs the
/// folder, or replaces the pack installed under its name.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PackPutRequest {
    pub files: Vec<PackFileInput>,
}

impl PackPutRequest {
    /// The folder as the pack source reads it.
    ///
    /// # Errors
    /// A bad request naming the first file whose base64 does not decode.
    pub fn into_files(self) -> MemoryResult<Vec<HubFile>> {
        decode_pack_files(self.files).map_err(|error| MemoryError::bad_request(error.to_string()))
    }
}

/// `vault.packs.remove`'s input: the installed pack to remove, by name.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PackRemoveRequest {
    pub pack: String,
}

/// `vault.connectors.subscriptions.put`'s input: the agent that answers a
/// built-in channel (OF-519), and the channel, `slack`, `line` or `email`.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ChannelSubscriptionRequest {
    /// The agent, as 32 hex.
    pub agent: String,
    pub channel: String,
}

/// `vault.connectors.subscriptions.list`'s input: whose subscriptions.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ChannelSubscriptionsRequest {
    /// The agent, as 32 hex.
    pub agent: String,
}

/// `vault.connectors.subscriptions.revoke`'s input: the subscription to stop.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ChannelSubscriptionRevokeRequest {
    /// The subscription, as 32 hex.
    pub subscription: String,
}

/// One part of an `ai.*` call on the SDK wire: text, or bytes as base64.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum AiPart {
    Text {
        text: String,
    },
    Image {
        media_type: String,
        data: String,
    },
    Audio {
        media_type: String,
        data: String,
    },
    /// A clip's bytes, or where its provider keeps it.
    Video {
        media_type: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        data: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        uri: Option<String>,
    },
    Embedding {
        vector: Vec<f32>,
    },
}

impl AiPart {
    /// The part a call sends: text, or an image or audio with base64 data.
    /// A clip or a vector is an answer, never an input.
    #[must_use]
    pub fn into_media(self) -> Option<MediaPart> {
        let bytes = |data: &str| STANDARD.decode(data).ok().filter(|bytes| !bytes.is_empty());
        Some(match self {
            Self::Text { text } => MediaPart::Text { text },
            Self::Image { media_type, data } => MediaPart::Image {
                bytes: bytes(&data)?,
                media_type,
            },
            Self::Audio { media_type, data } => MediaPart::Audio {
                bytes: bytes(&data)?,
                media_type,
            },
            Self::Video { .. } | Self::Embedding { .. } => return None,
        })
    }

    #[must_use]
    pub fn from_media(part: MediaPart) -> Self {
        match part {
            MediaPart::Text { text } => Self::Text { text },
            MediaPart::Image { media_type, bytes } => Self::Image {
                media_type,
                data: STANDARD.encode(bytes),
            },
            MediaPart::Audio { media_type, bytes } => Self::Audio {
                media_type,
                data: STANDARD.encode(bytes),
            },
            MediaPart::Video {
                media_type,
                bytes,
                uri,
            } => Self::Video {
                media_type,
                data: (!bytes.is_empty()).then(|| STANDARD.encode(bytes)),
                uri,
            },
            MediaPart::Embedding { vector } => Self::Embedding { vector },
        }
    }
}

/// An image-edit mask on the SDK and HTTP wires: image bytes as base64.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AiImageMask {
    pub media_type: String,
    pub data: String,
}

impl AiImageMask {
    #[must_use]
    pub fn into_image(self) -> Option<oneiron_model::llm::image::ImageBytes> {
        let bytes = STANDARD
            .decode(self.data)
            .ok()
            .filter(|bytes| !bytes.is_empty())?;
        Some(oneiron_model::llm::image::ImageBytes {
            bytes,
            media_type: self.media_type,
        })
    }
}

/// One `ai.*` media call: `ai.image`, `ai.video`, `ai.speech`,
/// `ai.transcribe` or `ai.embed`, as `POST /v1/ai/<operation>` takes it.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AiCallRequest {
    /// A row's id to use it alone, or its seat's id; the operation's seat
    /// when absent (`ai.options` lists both).
    #[serde(default)]
    pub model: Option<String>,
    /// The instruction, the script or the one text: a first text part.
    #[serde(default)]
    pub prompt: Option<String>,
    #[serde(default)]
    pub input: Vec<AiPart>,
    /// The images an image call edits, or a video call starts from.
    #[serde(default)]
    pub references: Vec<AiPart>,
    /// An explicit mask for an image edit; absent calls are unchanged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mask: Option<AiImageMask>,
    #[serde(default)]
    pub params: BTreeMap<String, serde_json::Value>,
    /// A speech call's voice; the provider's default when absent. Any
    /// other call that names one is refused.
    #[serde(default)]
    pub voice: Option<AiVoice>,
    /// The caller's own idempotency key for the call (FIX 2962): a repeat
    /// of the same call under the same key answers the first's answer, or
    /// a video's first ticket, and is not paid for or rendered again. A
    /// call in a banked voice is never replayed. With none, every call
    /// goes out.
    #[serde(default)]
    pub idempotency_key: Option<String>,
}

/// The voice an `ai.speech` call names (OF-410): a provider's stock voice
/// by its name, or a banked identity. A banked voice renders on the first
/// rung of the call's ladder whose target holds its current clone or
/// reference, and on that rung alone; with none, or once withdrawn, the call
/// is refused rather than spoken in another voice (ARCH-0061 §5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum AiVoice {
    /// A provider's own voice, by its name.
    Stock { name: String },
    /// A banked identity, rendered as its clone on the call's target.
    Bank {
        voice_id: String,
        #[serde(default)]
        include_generated: bool,
    },
}

/// One `ai.*` call's answer: the model that answered, its parts, and what
/// its provider counted.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AiAnswer {
    pub model: String,
    pub parts: Vec<AiPart>,
    pub usage: MediaUsage,
}

impl From<MediaResponse> for AiAnswer {
    fn from(response: MediaResponse) -> Self {
        Self {
            model: response.model.to_string(),
            parts: response.parts.into_iter().map(AiPart::from_media).collect(),
            usage: response.usage,
        }
    }
}

/// `ai.options`'s input: the operation whose rows to list (`text`, `image`,
/// `video`, `speech`, `transcribe`, `embed`), every one when absent, and the
/// modalities a call would send (`text`, `image`, `audio`, `video`,
/// `embedding`).
#[derive(Debug, Clone, Default, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AiOptionsRequest {
    #[serde(default)]
    pub operation: Option<String>,
    #[serde(default)]
    pub inputs: Vec<String>,
}

/// A video job, by the ticket `ai.video` answered.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AiVideoJobRequest {
    pub job: String,
}
pub mod ask_image;
pub mod hooks_replay;
pub mod pack_setup;
