//! The `oneiron.bm25_rank_profile.v1` rank profile file: BM25F weights for one keyword run.
//!
//! `--rank-profile` omitted resolves to the compiled default, read from the
//! store's `Bm25Config::default()`, never from literals. The resolved file
//! maps to the store's scoring-only `Bm25RankProfile`, so validation stays
//! the store's; the tuner re-resolves through the same body.

use oneiron::analyzer::AnalyzerChannel;
use oneiron::config::Bm25RankProfile;
use oneiron::config::bm25::{Bm25Config, Bm25Formula};

use super::ScorecardFailure;

/// The contract string every rank profile file carries.
pub(crate) const PROFILE_CONTRACT: &str = "oneiron.bm25_rank_profile.v1";

/// The profile of one keyword run: the store profile and the digest over the resolved file.
#[derive(Clone, Debug)]
pub(crate) struct ResolvedProfile {
    /// The explicit store profile the file names (even when it spells the default).
    pub(crate) profile: Bm25RankProfile,
    /// The exact JSON object the digest is computed over, in the file's shape.
    pub(crate) resolved: serde_json::Value,
    /// The digest over the resolved file.
    pub(crate) digest: String,
    /// True when the four (weight, b) pairs and the formula equal the compiled default's exactly.
    pub(crate) is_default: bool,
}

/// Which number of a channel a tuner step sets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ChannelField {
    /// The channel's scoring weight.
    Weight,
    /// The channel's BM25 length norm.
    B,
}

/// One channel's numbers in a profile file.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ChannelFile {
    weight: f64,
    b: f64,
}

/// The four channels of a profile file.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ChannelsFile {
    surface: ChannelFile,
    stem: ChannelFile,
    normalized_overlay: ChannelFile,
    cjk_ngram: ChannelFile,
}

/// The formula of a profile file.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct FormulaFile {
    kind: String,
    #[serde(default)]
    delta: Option<f64>,
}

/// A rank profile file.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ProfileFile {
    contract: String,
    formula: FormulaFile,
    channels: ChannelsFile,
}

/// Resolve `--rank-profile` (or its absence) into the store profile and the digest.
pub(crate) fn resolve_profile(path: Option<&str>) -> Result<ResolvedProfile, ScorecardFailure> {
    match path {
        None => resolve_value(&default_value()),
        Some(path) => {
            let bytes = std::fs::read(path).map_err(|error| {
                ScorecardFailure::Input(format!("rank profile read failed: {error}"))
            })?;
            let file: serde_json::Value = serde_json::from_slice(&bytes).map_err(|error| {
                ScorecardFailure::Input(format!("rank profile parse failed: {error}"))
            })?;
            resolve_value(&file)
        }
    }
}

/// Set one channel's weight or b on a resolved profile and re-resolve.
///
/// The value travels through the same file shape, store validation and
/// digest as a file load, so the tuner can never build a profile a file
/// could not name.
pub(crate) fn with_channel_field(
    base: &ResolvedProfile,
    channel: AnalyzerChannel,
    field: ChannelField,
    value: f64,
) -> Result<ResolvedProfile, ScorecardFailure> {
    let mut next = base.resolved.clone();
    let name = channel.as_str();
    let key = match field {
        ChannelField::Weight => "weight",
        ChannelField::B => "b",
    };
    let fail = || ScorecardFailure::Run(format!("resolved profile misses channel {name} {key}"));
    let Some(channels) = next.get_mut("channels") else {
        return Err(fail());
    };
    let Some(entry) = channels.get_mut(name) else {
        return Err(fail());
    };
    let Some(slot) = entry.get_mut(key) else {
        return Err(fail());
    };
    *slot = serde_json::Value::from(value);
    resolve_value(&next)
}

/// Read one channel's weight or b from a resolved profile.
pub(crate) fn channel_value(
    resolved: &ResolvedProfile,
    channel: AnalyzerChannel,
    field: ChannelField,
) -> Result<f64, ScorecardFailure> {
    let name = channel.as_str();
    let key = match field {
        ChannelField::Weight => "weight",
        ChannelField::B => "b",
    };
    let fail = || ScorecardFailure::Run(format!("resolved profile misses channel {name} {key}"));
    let Some(channels) = resolved.resolved.get("channels") else {
        return Err(fail());
    };
    let Some(entry) = channels.get(name) else {
        return Err(fail());
    };
    let Some(value) = entry.get(key).and_then(serde_json::Value::as_f64) else {
        return Err(fail());
    };
    Ok(value)
}

/// Resolve one parsed profile value: contract, numbers, store profile, digest.
fn resolve_value(file: &serde_json::Value) -> Result<ResolvedProfile, ScorecardFailure> {
    let parsed: ProfileFile = serde_json::from_value(file.clone())
        .map_err(|error| ScorecardFailure::Input(format!("bad rank profile: {error}")))?;
    let contract = parsed.contract.as_str();
    if contract != PROFILE_CONTRACT {
        return Err(ScorecardFailure::Input(format!(
            "wrong contract: {contract}"
        )));
    }
    let formula = match parsed.formula.kind.as_str() {
        "okapi" => {
            if parsed.formula.delta.is_some() {
                return Err(ScorecardFailure::Input("okapi takes no delta".to_owned()));
            }
            Bm25Formula::Okapi
        }
        "plus" => {
            let Some(delta) = parsed.formula.delta else {
                return Err(ScorecardFailure::Input("plus needs its delta".to_owned()));
            };
            Bm25Formula::Plus { delta }
        }
        other => {
            return Err(ScorecardFailure::Input(format!("unknown formula: {other}")));
        }
    };
    let channels = [
        (AnalyzerChannel::Surface, &parsed.channels.surface),
        (AnalyzerChannel::Stem, &parsed.channels.stem),
        (
            AnalyzerChannel::NormalizedOverlay,
            &parsed.channels.normalized_overlay,
        ),
        (AnalyzerChannel::CjkNgram, &parsed.channels.cjk_ngram),
    ];
    let mut profile = Bm25RankProfile::default().with_formula(formula);
    for (channel, numbers) in &channels {
        profile = profile
            .with_channel_weight(*channel, numbers.weight)
            .with_channel_b(*channel, numbers.b);
    }
    let validated = profile
        .to_bm25_config()
        .map_err(|error| ScorecardFailure::Input(format!("bad rank profile: {error}")))?;
    let resolved = profile_json(&validated);
    let digest = profile_digest(&resolved)?;
    let defaults = Bm25Config::default();
    let mut is_default = validated.formula == defaults.formula;
    for channel in AnalyzerChannel::ALL_V1 {
        let field = validated.field(channel);
        let want = defaults.field(channel);
        is_default = is_default
            && field.weight.total_cmp(&want.weight) == std::cmp::Ordering::Equal
            && field.b.total_cmp(&want.b) == std::cmp::Ordering::Equal;
    }
    Ok(ResolvedProfile {
        profile,
        resolved,
        digest,
        is_default,
    })
}

/// The compiled default in the file's shape, read from `Bm25Config::default()`.
fn default_value() -> serde_json::Value {
    let defaults = Bm25Config::default();
    profile_json(&defaults)
}

/// The file-shaped JSON of validated numbers: contract, formula, channels.
fn profile_json(config: &Bm25Config) -> serde_json::Value {
    let mut channels = serde_json::Map::with_capacity(AnalyzerChannel::ALL_V1.len());
    for channel in AnalyzerChannel::ALL_V1 {
        let field = config.field(channel);
        channels.insert(
            channel.as_str().to_owned(),
            serde_json::json!({"weight": field.weight, "b": field.b}),
        );
    }
    serde_json::json!({
        "contract": PROFILE_CONTRACT,
        "formula": formula_json(&config.formula),
        "channels": channels,
    })
}

/// The file-shaped JSON of a validated formula.
fn formula_json(formula: &Bm25Formula) -> serde_json::Value {
    match formula {
        Bm25Formula::Okapi => serde_json::json!({"kind": "okapi"}),
        Bm25Formula::Plus { delta } => serde_json::json!({"kind": "plus", "delta": delta}),
    }
}

/// The profile digest: sha256 over the canonical bytes of the resolved file.
fn profile_digest(resolved: &serde_json::Value) -> Result<String, ScorecardFailure> {
    let canonical = serde_json_canonicalizer::to_vec(resolved)
        .map_err(|error| ScorecardFailure::Run(format!("rank profile digest failed: {error}")))?;
    Ok(oneiron_ruler::pack::sha256_hex(&canonical))
}
