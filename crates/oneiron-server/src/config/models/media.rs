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
//!
//! [models.media.speech]
//! rungs = ["cartesia-compat:sonic", "local:voxcpm2"]
//! tiers = { "tts-live" = "local:voxcpm2", "tts-deferred" = "local:voxcpm2" }
//! ```
//!
//! A speech or transcription seat's `tiers` bind voice tiers to its rungs:
//! the vault's voice rows (`asr-live`, `tts-live`, ...) name a tier, and the
//! voice cascade speaks or hears on the one rung bound to it. A rung no
//! tier names serves `ai.speech` and `ai.transcribe` calls only.
//!
//! A soniox rung hears live, over its own socket, and serves the voice
//! cascade only. Its `rung_options` carry the languages it listens for:
//!
//! ```toml
//! [models.media.transcribe]
//! rungs = ["soniox:stt-rt-v5"]
//! tiers = { "asr-live" = "soniox:stt-rt-v5" }
//!
//! [models.media.transcribe.rung_options."soniox:stt-rt-v5"]
//! language_hints = ["ja", "en"]
//! ```
use std::collections::{BTreeMap, BTreeSet};

use oneiron::ModelTierRef;
use oneiron::llm::media::{AiOperation, MediaCaps, Modality, NativeRate};
use serde::Deserialize;

use super::levels::ModelRef;
use super::provider::{ProviderConfig, ProviderKind};

/// Process-lifetime meter for the `ai.*` media calls.
const DEFAULT_MEDIA_BUDGET_UNITS: u64 = 10_000_000;
/// The languages a live soniox rung listens for when its `rung_options`
/// name none (CALLS.md: Soniox language hints).
const DEFAULT_LIVE_ASR_LANGUAGE_HINTS: [&str; 2] = ["ja", "en"];

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
    /// Voice tier -> the rung (`"<provider>:<model>"`) that serves it.
    #[serde(default)]
    tiers: BTreeMap<String, String>,
    /// Rung (`"<provider>:<model>"`) -> its live-ASR options.
    #[serde(default)]
    rung_options: BTreeMap<String, RungOptionsFile>,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct RungOptionsFile {
    language_hints: Option<Vec<String>>,
}

/// What a live transcribe rung sends when its socket opens.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LiveAsrOptions {
    /// The languages it listens for, in order; config replaces the default.
    pub language_hints: Vec<String>,
}

impl Default for LiveAsrOptions {
    fn default() -> Self {
        Self {
            language_hints: DEFAULT_LIVE_ASR_LANGUAGE_HINTS
                .iter()
                .map(|hint| (*hint).to_owned())
                .collect(),
        }
    }
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
    /// The voice tiers its rungs serve, each bound to one rung.
    pub tiers: BTreeMap<ModelTierRef, ModelRef>,
    /// Each live (soniox) rung's options, defaults filled in.
    pub live_asr: BTreeMap<ModelRef, LiveAsrOptions>,
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
                ) || (provider.kind.speech_only() && operation == AiOperation::Speech)
                    || (provider.kind == ProviderKind::Gemini
                        && matches!(operation, AiOperation::Image | AiOperation::Video))
                    || (provider.kind == ProviderKind::Soniox
                        && operation == AiOperation::Transcribe),
                "models.media.{key}: {model} is not on an OpenAI-compatible provider; media calls speak its /v1 media paths, a cartesia, elevenlabs or voxcpm2 provider serves the speech seat only, a gemini provider the image and video seats only, and a soniox provider the transcribe seat only"
            );
            // A key_secret provider's media calls go through the credential
            // broker, which has a shape for every OpenAI-compatible media
            // path and for the Gemini API's image and video calls.
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
        anyhow::ensure!(
            self.tiers.is_empty()
                || matches!(operation, AiOperation::Speech | AiOperation::Transcribe),
            "models.media.{key}.tiers: only the speech and transcribe seats serve voice tiers"
        );
        let mut tiers = BTreeMap::new();
        for (tier, rung) in self.tiers {
            anyhow::ensure!(
                !tier.trim().is_empty(),
                "models.media.{key}.tiers: a tier has a name"
            );
            let model = ModelRef::parse(&format!("models.media.{key}.tiers.{tier}"), &rung)?;
            anyhow::ensure!(
                rungs.contains(&model),
                "models.media.{key}.tiers.{tier}: {model} is not one of this seat's rungs"
            );
            tiers.insert(ModelTierRef(tier), model);
        }
        let live_asr = live_asr_options(key, &rungs, providers, self.rung_options)?;
        Ok(MediaSeatConfig {
            rungs,
            caps,
            tiers,
            live_asr,
        })
    }
}

/// Every soniox rung's options: what `rung_options` names for it, else the
/// default. Options for any other rung, or one the seat does not list, are
/// refused rather than ignored.
fn live_asr_options(
    key: &str,
    rungs: &[ModelRef],
    providers: &BTreeMap<String, ProviderConfig>,
    files: BTreeMap<String, RungOptionsFile>,
) -> anyhow::Result<BTreeMap<ModelRef, LiveAsrOptions>> {
    let mut named = BTreeMap::new();
    for (rung, file) in files {
        let model = ModelRef::parse(&format!("models.media.{key}.rung_options"), &rung)?;
        anyhow::ensure!(
            rungs.contains(&model),
            "models.media.{key}.rung_options: {model} is not one of this seat's rungs"
        );
        named.insert(model, file);
    }
    let mut live = BTreeMap::new();
    for model in rungs {
        let soniox = providers
            .get(&model.provider)
            .is_some_and(|provider| provider.kind == ProviderKind::Soniox);
        let file = named.remove(model);
        if !soniox {
            anyhow::ensure!(
                file.is_none(),
                "models.media.{key}.rung_options: {model} is not a soniox rung; only a live transcribe rung takes options"
            );
            continue;
        }
        let mut options = LiveAsrOptions::default();
        if let Some(hints) = file.and_then(|file| file.language_hints) {
            anyhow::ensure!(
                !hints.is_empty() && hints.iter().all(|hint| is_language_hint(hint)),
                "models.media.{key}.rung_options.\"{model}\".language_hints: name one or more language codes (a-z, '-')"
            );
            options.language_hints = hints;
        }
        live.insert(model.clone(), options);
    }
    Ok(live)
}

fn is_language_hint(hint: &str) -> bool {
    !hint.is_empty()
        && hint.len() <= 16
        && hint.bytes().all(|b| b.is_ascii_lowercase() || b == b'-')
}
