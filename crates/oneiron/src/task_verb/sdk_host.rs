//! The inputs and answers of the verb-table rows a host door answers: the
//! owner's `vault.packs.put` and the `ai.*` model calls past text. A server
//! answers each with its own state (the owner's proof, its model seats); an
//! embedded handle answers a pack put as the vault's embedded owner and
//! refuses an `ai.*` call, which has no seat to run on there.
use std::collections::BTreeMap;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde::{Deserialize, Serialize};

use crate::llm::media::{AiOperation, MediaJobState, MediaPart, MediaResponse, MediaUsage};
use crate::memory::{MEMORY_CODE_MODEL_UNAVAILABLE, Memory, MemoryError, MemoryResult};
use crate::skill_hub::HubFile;
use crate::skill_hub::pack_catalog::{PackInstallDisposition, PackInstallReceipt};

/// One file of a pack folder.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PackFileInput {
    /// Relative to the pack folder, `/`-separated.
    pub path: String,
    pub text: String,
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
    #[must_use]
    pub fn into_files(self) -> Vec<HubFile> {
        self.files
            .into_iter()
            .map(|file| HubFile::new(file.path, file.text.into_bytes()))
            .collect()
    }
}

/// What one pack put did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PackPutOutcome {
    Installed,
    /// Its code waits for its sandbox to qualify it.
    Candidate,
    /// The vault's install rules refused it; `reason` says why.
    Blocked,
}

/// `vault.packs.put`'s answer: the outcome, and the install receipt unless
/// the put was blocked.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackPutReceipt {
    pub outcome: PackPutOutcome,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt: Option<Box<PackInstallReceipt>>,
}

impl From<PackInstallDisposition> for PackPutReceipt {
    fn from(disposition: PackInstallDisposition) -> Self {
        let (outcome, reason, receipt) = match disposition {
            PackInstallDisposition::Installed(receipt) => {
                (PackPutOutcome::Installed, None, Some(receipt))
            }
            PackInstallDisposition::Candidate(receipt) => {
                (PackPutOutcome::Candidate, None, Some(receipt))
            }
            PackInstallDisposition::Blocked { reason } => {
                (PackPutOutcome::Blocked, Some(reason), None)
            }
        };
        Self {
            outcome,
            reason,
            receipt,
        }
    }
}

/// `vault.packs.put` under the owner's proof a host minted from the request.
pub fn put_pack_as_owner(
    vault: &crate::Vault,
    owner: &crate::consent::AuthenticatedOwner,
    input: PackPutRequest,
) -> MemoryResult<PackPutReceipt> {
    Ok(vault.put_pack(owner, input.into_files())?.into())
}

/// `vault.packs.put` on an embedded handle: the vault's embedded owner's put.
pub fn put_pack_embedded(
    memory: &Memory<'_>,
    input: PackPutRequest,
) -> MemoryResult<PackPutReceipt> {
    Ok(memory
        .put_pack_as_embedded_owner(input.into_files())?
        .into())
}

/// A row only a host's own state answers, refused on an embedded handle.
pub fn host_only<T, I>(_memory: &Memory<'_>, verb: &str, _input: &I) -> MemoryResult<T> {
    Err(MemoryError::new(
        MEMORY_CODE_MODEL_UNAVAILABLE,
        format!("{verb} runs on a server's model seats; an embedded vault has none"),
        &["Call it through a remote client of a server with a [models.media] seat."],
    ))
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
    #[serde(default)]
    pub params: BTreeMap<String, serde_json::Value>,
}

/// One `ai.*` call's answer: the model that answered, its parts, and what
/// its provider counted.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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

/// `ai.options`'s answer: each text seat's rungs and each media row that
/// serves the operation over those inputs, and what the media meter has left.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiOptions {
    pub options: Vec<serde_json::Value>,
    pub media_units_left: Option<u64>,
}

/// `ai.video`'s answer: the provider job its clip renders as.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiVideoTicket {
    pub job: String,
    pub model: String,
    pub operation: AiOperation,
}

/// A video job, by the ticket `ai.video` answered.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AiVideoJobRequest {
    pub job: String,
}

/// Where a video job stands; a finished one answers with its clip, once.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum AiVideoJob {
    Queued,
    Running {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        progress: Option<u8>,
    },
    Done {
        answer: AiAnswer,
    },
    Failed {
        error: crate::LlmError,
    },
}

impl From<MediaJobState> for AiVideoJob {
    fn from(state: MediaJobState) -> Self {
        match state {
            MediaJobState::Queued => Self::Queued,
            MediaJobState::Running { progress } => Self::Running { progress },
            MediaJobState::Done { response } => Self::Done {
                answer: response.into(),
            },
            MediaJobState::Failed { error } => Self::Failed { error },
        }
    }
}

/// `ai.video.cancel`'s answer: the job its provider was told to stop.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiVideoCancelled {
    pub job: String,
}
