//! Media call operations, modalities and row capabilities.
//! Entry: AiOperation.
//! Definitions: this module; the parent re-exports the old paths.

use super::{BTreeSet, Deserialize, NativeRate, Serialize};

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

/// What one model row serves past text: its operations, the modalities its
/// calls take in and put out, and the rates its native counts settle at.
/// A catalog row carries it under its `media` metadata
/// ([`crate::llm::LlmCatalogEntry::media`]).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MediaCaps {
    pub operations: BTreeSet<AiOperation>,
    pub inputs: BTreeSet<Modality>,
    pub outputs: BTreeSet<Modality>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub native_rates: Vec<NativeRate>,
    /// How many reference images the seat's offers are said to take: an
    /// advisory hint an options listing shows, 0 when unsaid. Nothing
    /// refuses a call by it; an offer whose wire cannot carry a call's whole
    /// reference set says so itself
    /// ([`MediaBackend::reference_compatibility`](super::MediaBackend::reference_compatibility)),
    /// and the call goes to an offer that can (FIX 8627).
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
            max_references: 0,
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
