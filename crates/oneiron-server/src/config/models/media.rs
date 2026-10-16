//! `[models.media]`: the media seats (ODM-004: image, video and the rest
//! are seats outside the tiers). Each operation's seat is a ladder of
//! `"<provider>:<model>"` rungs on OpenAI-compatible providers, with the
//! inputs its calls take and the rates its native counts settle at.
//!
//! ```toml
//! [models.media]
//! budget_units = 10000000
//!
//! [models.media.image]
//! rungs = ["openai:gpt-image-1", "local:flux-schnell"]
//! max_references = 8
//! rates = [{ unit = "image", per = 1, tokens = 4000 }]
//! ```
use std::collections::{BTreeMap, BTreeSet};

use oneiron::llm::media::{AiOperation, MediaCaps, Modality, NativeRate};
use serde::Deserialize;

use super::levels::ModelRef;
use super::provider::{ProviderConfig, ProviderKind};

/// Process-lifetime meter for the `ai.*` media calls.
const DEFAULT_MEDIA_BUDGET_UNITS: u64 = 10_000_000;

#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct MediaFile {
    budget_units: Option<u64>,
    image: Option<MediaSeatFile>,
    video: Option<MediaSeatFile>,
    speech: Option<MediaSeatFile>,
    transcribe: Option<MediaSeatFile>,
    embed: Option<MediaSeatFile>,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct MediaSeatFile {
    rungs: Vec<String>,
    inputs: Option<BTreeSet<Modality>>,
    max_references: Option<usize>,
    #[serde(default)]
    rates: Vec<NativeRate>,
}

/// The resolved `[models.media]`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MediaSettings {
    pub budget_units: u64,
    pub seats: BTreeMap<AiOperation, MediaSeatConfig>,
}

impl Default for MediaSettings {
    fn default() -> Self {
        Self {
            budget_units: DEFAULT_MEDIA_BUDGET_UNITS,
            seats: BTreeMap::new(),
        }
    }
}

/// One operation's seat: its rungs in fallback order, and what each serves.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MediaSeatConfig {
    pub rungs: Vec<ModelRef>,
    pub caps: MediaCaps,
}

impl MediaFile {
    pub(super) fn resolve(
        self,
        providers: &BTreeMap<String, ProviderConfig>,
    ) -> anyhow::Result<MediaSettings> {
        let budget_units = self.budget_units.unwrap_or(DEFAULT_MEDIA_BUDGET_UNITS);
        anyhow::ensure!(
            budget_units > 0,
            "models.media.budget_units must be greater than zero"
        );
        let mut seats = BTreeMap::new();
        for (operation, file) in [
            (AiOperation::Image, self.image),
            (AiOperation::Video, self.video),
            (AiOperation::Speech, self.speech),
            (AiOperation::Transcribe, self.transcribe),
            (AiOperation::Embed, self.embed),
        ] {
            if let Some(file) = file {
                seats.insert(operation, file.resolve(operation, providers)?);
            }
        }
        Ok(MediaSettings {
            budget_units,
            seats,
        })
    }
}

impl MediaSeatFile {
    fn resolve(
        self,
        operation: AiOperation,
        providers: &BTreeMap<String, ProviderConfig>,
    ) -> anyhow::Result<MediaSeatConfig> {
        let key = operation.as_str();
        let mut rungs = Vec::new();
        for value in &self.rungs {
            let model = ModelRef::parse(&format!("models.media.{key}.rungs"), value)?;
            let provider = providers.get(&model.provider).ok_or_else(|| {
                anyhow::anyhow!(
                    "models.media.{key}: {model} names provider {:?}, which [models.providers] does not define",
                    model.provider
                )
            })?;
            anyhow::ensure!(
                matches!(
                    provider.kind,
                    ProviderKind::OpenaiCompat | ProviderKind::LocalOpenaiCompat
                ),
                "models.media.{key}: {model} is not on an OpenAI-compatible provider; media calls speak its /v1 media paths"
            );
            // The credential broker sends chat calls only. A media call sent
            // without it would carry no key, while its offer says the broker
            // holds one.
            anyhow::ensure!(
                provider.key_secret.is_none(),
                "models.media.{key}: {model} is on a key_secret provider; the credential broker sends chat calls only"
            );
            anyhow::ensure!(
                !rungs.contains(&model),
                "models.media.{key}: {model} appears twice in one ladder"
            );
            rungs.push(model);
        }
        anyhow::ensure!(!rungs.is_empty(), "models.media.{key}.rungs is empty");
        let mut caps = MediaCaps::for_operation(operation);
        if let Some(inputs) = self.inputs {
            caps.inputs = inputs;
        }
        if let Some(max_references) = self.max_references {
            caps.max_references = max_references;
        }
        for rate in self.rates {
            anyhow::ensure!(
                rate.per > 0,
                "models.media.{key}.rates: per must be greater than zero"
            );
            caps.native_rates.retain(|known| known.unit != rate.unit);
            caps.native_rates.push(rate);
        }
        Ok(MediaSeatConfig { rungs, caps })
    }
}
