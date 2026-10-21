//! Media call requests and voices.
//! Entry: MediaPart.
//! Definitions: this module; the parent re-exports the old paths.

use super::{
    AiOperation, BTreeMap, BTreeSet, CallEnvelope, Deserialize, FatalLlmError, ImageBytes,
    ImageIntent, JsonValue, LlmRequest, LlmResult, Modality, ModelId, Serialize,
};

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
/// render-target law) lives in the vault's reference bank. A cloning
/// provider only ever sees its target's recorded voice id for it; a target
/// that keeps no clone (an own-server VoxCPM2 worker) gets the identity's
/// reference clip with each call. The host resolved either from the bank
/// for this call's rung.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum MediaVoice {
    /// The provider's own voice, by its name: no banked identity.
    Stock { name: String },
    /// A banked identity's clone on this call's target: the provider's
    /// disposable id for it.
    Clone { id: String },
    /// A banked identity's own source clip and its transcript, fenced by
    /// the host at the bank's revision of the identity's refs. The clip is
    /// the person's raw voice: only a wire that renders from a reference
    /// takes it, and every other wire refuses the call.
    Reference {
        voice_id: String,
        /// The identity's owner, as the bank records it (hex).
        owner: String,
        register: String,
        /// The bank's revision of the identity's refs (hex): it changes
        /// when the refs change or the identity is banked again.
        revision: String,
        media_type: String,
        audio: Vec<u8>,
        transcript: String,
    },
}

impl MediaVoice {
    /// The name or id the provider's wire carries; `None` for a reference,
    /// which no wire names by id.
    #[must_use]
    pub fn wire_id(&self) -> Option<&str> {
        match self {
            Self::Stock { name } => Some(name),
            Self::Clone { id } => Some(id),
            Self::Reference { .. } => None,
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
        let bytes = crate::llm::canonical_json_bytes(self)?;
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
