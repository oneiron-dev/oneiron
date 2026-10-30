//! Media call answers, usage and job states.
//! Entry: MediaUsage.
//! Definitions: this module; the parent re-exports the old paths.

use super::{
    AiOperation, Deserialize, ImageBytes, ImageResponse, JsonValue, LlmError, MediaCaps, MediaPart,
    ModelId, NativeUnit, Serialize,
};

/// What a provider counted for one media call. Tokens when it counts
/// tokens; otherwise its native counts.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
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
    /// Whether the call's charge counts the provider's token report (FIX
    /// 11481): true when it reported any tokens, false when the charge
    /// falls back to the host/caller's own native counts at the row's
    /// rates.
    #[must_use]
    pub fn is_provider_counted(&self) -> bool {
        self.input_tokens.saturating_add(self.output_tokens) > 0
    }

    /// The call's charge in token units: the tokens the provider counted,
    /// else each native count at `caps`' rate for it. `None` when it
    /// counted nothing, so the run charges the call's reservation.
    #[must_use]
    pub fn token_units(&self, operation: AiOperation, caps: &MediaCaps) -> Option<u64> {
        if self.is_provider_counted() {
            return Some(self.input_tokens.saturating_add(self.output_tokens));
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

/// What a media call that sends several physical requests (a long text
/// spoken as several renders) completed before it stopped (FIX 9517): how
/// many of its requests answered, and their usage, each one's inference
/// receipt in it. A call stopped part way is settled on this, once, and its
/// partial output is no answer.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct MediaCallProgress {
    /// The physical requests that answered, in order.
    #[serde(default)]
    pub completed: u64,
    /// What they counted.
    #[serde(default)]
    pub usage: MediaUsage,
}

impl MediaCallProgress {
    /// Whether no request answered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.completed == 0
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
