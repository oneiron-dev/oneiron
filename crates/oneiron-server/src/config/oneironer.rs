//! The `[oneironer]` section: the tagger slot's provider, mode, endpoint
//! identity and label table.
//!
//! Opt-in like `[embedder]`: a server whose configuration never names the
//! section tags nothing and commits no tagging marker. Naming it selects a
//! provider, defaulting to the in-process local one (ARCH-0036: extraction
//! defaults to the device), which this build does not have yet.

use std::collections::BTreeMap;
use std::fmt;
use std::str::FromStr;

use clap::Args;
use serde::Deserialize;

use super::lookup::lookup_parse;

const DEFAULT_TIMEOUT_MS: u64 = 10_000;
const DEFAULT_BATCH_SIZE: usize = 16;
const DEFAULT_IDLE_INTERVAL_MS: u64 = 15_000;
const DEFAULT_RETRY_BACKOFF_SECS: u64 = 5;
const DEFAULT_MAX_RETRY_BACKOFF_SECS: u64 = 300;
const MAX_LABEL_BYTES: usize = 64;

/// Which tagger runs behind the slot.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum OneironerProvider {
    /// In-process on this machine. Not built yet: refused at startup.
    #[default]
    Local,
    /// A tagger server on this machine speaking the slot's contract
    /// (`GET /v1/model`, `POST /v1/extract`).
    Endpoint,
    /// No tagger and no marker.
    None,
}

impl OneironerProvider {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::Endpoint => "endpoint",
            Self::None => "none",
        }
    }
}

impl FromStr for OneironerProvider {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "local" => Ok(Self::Local),
            "endpoint" => Ok(Self::Endpoint),
            "none" => Ok(Self::None),
            other => Err(format!(
                "unknown oneironer provider {other:?} (expected local, endpoint or none)"
            )),
        }
    }
}

impl fmt::Display for OneironerProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What the slot does with a checked answer.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum OneironerMode {
    /// A vault with a tagger saves its tags (owner ruling 2026-09-29). Not
    /// built yet: refused at startup.
    #[default]
    Save,
    /// Tag and write nothing but the marker's settlement: the test switch.
    Shadow,
}

impl OneironerMode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Save => "save",
            Self::Shadow => "shadow",
        }
    }
}

impl FromStr for OneironerMode {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "save" => Ok(Self::Save),
            "shadow" => Ok(Self::Shadow),
            other => Err(format!(
                "unknown oneironer mode {other:?} (expected save or shadow)"
            )),
        }
    }
}

/// Fully resolved `[oneironer]` section.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OneironerConfig {
    pub provider: OneironerProvider,
    pub mode: OneironerMode,
    /// Base URL of the tagger server; the slot appends `/v1/model` and
    /// `/v1/extract`. Loopback only in this build.
    pub url: Option<String>,
    /// The checkpoint the tagger must report: 16 lowercase hex digits of the
    /// SHA-256 of its weights. Also half of every marker's dedupe key.
    pub checkpoint_sha16: Option<String>,
    /// How many labels the tagger must report.
    pub label_count: Option<u32>,
    /// Model label to engine entity kind (a registry kind such as `PERSON`).
    /// A label absent here stays a tag and maps to nothing.
    pub labels: BTreeMap<String, String>,
    /// Request timeout per tagger call.
    pub timeout_ms: u64,
    /// Markers claimed per worker pass.
    pub batch_size: usize,
    /// Longest the worker waits between passes when nothing wakes it.
    pub idle_interval_ms: u64,
    /// Delay before a failed marker's first retry; each retry doubles it.
    pub retry_backoff_secs: u64,
    /// Ceiling on the doubled retry delay.
    pub max_retry_backoff_secs: u64,
    /// The live window in the tagger's tokens: how much earlier text of its
    /// conversation a turn is sent with. Set it to the tagger's own K; it
    /// defaults to the serving runtime's 256 (`LIVE_K`); 0 sends each turn
    /// alone; at most 2,048. It bounds what the engine sends; the tagger cuts
    /// the window to its own K, which its model card does not declare yet.
    pub live_window_tokens: u32,
    /// Traces kept per turn once a settled marker leaves the job ledger.
    /// Defaults to 4; 0 keeps none; at most 1,024.
    pub trace_history_per_turn: u32,
    /// Store-clock seconds a trace is kept. Defaults to seven days.
    pub trace_history_max_age_secs: u64,
}

impl Default for OneironerConfig {
    fn default() -> Self {
        Self {
            provider: OneironerProvider::default(),
            mode: OneironerMode::default(),
            url: None,
            checkpoint_sha16: None,
            label_count: None,
            labels: BTreeMap::new(),
            timeout_ms: DEFAULT_TIMEOUT_MS,
            batch_size: DEFAULT_BATCH_SIZE,
            idle_interval_ms: DEFAULT_IDLE_INTERVAL_MS,
            retry_backoff_secs: DEFAULT_RETRY_BACKOFF_SECS,
            max_retry_backoff_secs: DEFAULT_MAX_RETRY_BACKOFF_SECS,
            live_window_tokens: oneiron::tagging::DEFAULT_LIVE_WINDOW_TOKENS,
            trace_history_per_turn: oneiron::tagging::DEFAULT_TRACES_PER_TURN,
            trace_history_max_age_secs: oneiron::tagging::DEFAULT_TRACE_MAX_AGE_SECS,
        }
    }
}

impl OneironerConfig {
    /// Whether this section commits markers and runs a worker.
    pub const fn is_active(&self) -> bool {
        !matches!(self.provider, OneironerProvider::None)
    }

    /// The checkpoint a write's marker is committed for, when markers are on.
    ///
    /// Only an endpoint arms markers in this build: the local provider and
    /// save mode stop `serve` before a write could commit one.
    pub fn marker_checkpoint(&self) -> Option<&str> {
        (self.provider == OneironerProvider::Endpoint)
            .then_some(self.checkpoint_sha16.as_deref())
            .flatten()
    }

    /// The vault's marker configuration, when markers are on: the checkpoint,
    /// the live window and the trace history.
    pub fn marker_config(&self) -> Option<oneiron::tagging::TaggingMarkerConfig> {
        let checkpoint = self.marker_checkpoint()?;
        Some(oneiron::tagging::TaggingMarkerConfig {
            checkpoint: checkpoint.to_owned(),
            live_window_tokens: self.live_window_tokens,
            trace_history: self.trace_history(),
        })
    }

    fn trace_history(&self) -> oneiron::tagging::TaggingTraceHistory {
        oneiron::tagging::TaggingTraceHistory {
            per_turn: self.trace_history_per_turn,
            max_age_secs: self.trace_history_max_age_secs,
        }
    }

    /// The label table as engine type bytes. Validation guarantees every kind
    /// names a registry entry.
    pub fn label_kinds(&self) -> BTreeMap<String, u8> {
        self.labels
            .iter()
            .filter_map(|(label, kind)| registry_type_byte(kind).map(|byte| (label.clone(), byte)))
            .collect()
    }

    pub(super) fn apply_override(&mut self, over: OneironerConfigOverride) {
        if let Some(value) = over.provider {
            self.provider = value;
        }
        if let Some(value) = over.mode {
            self.mode = value;
        }
        if over.url.is_some() {
            self.url = over.url;
        }
        if over.checkpoint_sha16.is_some() {
            self.checkpoint_sha16 = over.checkpoint_sha16;
        }
        if over.label_count.is_some() {
            self.label_count = over.label_count;
        }
        if let Some(labels) = over.labels {
            self.labels = labels;
        }
        if let Some(value) = over.timeout_ms {
            self.timeout_ms = value;
        }
        if let Some(value) = over.batch_size {
            self.batch_size = value;
        }
        if let Some(value) = over.idle_interval_ms {
            self.idle_interval_ms = value;
        }
        if let Some(value) = over.retry_backoff_secs {
            self.retry_backoff_secs = value;
        }
        if let Some(value) = over.max_retry_backoff_secs {
            self.max_retry_backoff_secs = value;
        }
        if let Some(value) = over.live_window_tokens {
            self.live_window_tokens = value;
        }
        if let Some(value) = over.trace_history_per_turn {
            self.trace_history_per_turn = value;
        }
        if let Some(value) = over.trace_history_max_age_secs {
            self.trace_history_max_age_secs = value;
        }
    }

    /// Refuses a section that cannot produce a working slot. The local
    /// provider and save mode pass here and are refused, typed, when the slot
    /// is built.
    pub fn validate(&self) -> anyhow::Result<()> {
        if self.live_window_tokens > oneiron::tagging::MAX_LIVE_WINDOW_TOKENS {
            anyhow::bail!("oneironer.live_window_tokens must be at most 2048");
        }
        if self.trace_history_per_turn > oneiron::tagging::MAX_TRACES_PER_TURN {
            anyhow::bail!("oneironer.trace_history_per_turn must be at most 1024");
        }
        if self.trace_history_max_age_secs == 0 {
            anyhow::bail!("oneironer.trace_history_max_age_secs must be greater than zero");
        }
        for (label, kind) in &self.labels {
            if label.is_empty() || label.len() > MAX_LABEL_BYTES {
                anyhow::bail!("oneironer.labels keys must be 1 to 64 bytes");
            }
            if registry_type_byte(kind).is_none() {
                anyhow::bail!("oneironer.labels maps a label to unknown entity kind {kind:?}");
            }
        }
        if self.provider != OneironerProvider::Endpoint {
            return Ok(());
        }
        if self.url.as_deref().unwrap_or_default().trim().is_empty() {
            anyhow::bail!(
                "oneironer.provider = \"endpoint\" requires oneironer.url (--oneironer-url / ONEIRON_ONEIRONER_URL)"
            );
        }
        let checkpoint = self.checkpoint_sha16.as_deref().unwrap_or_default();
        if oneiron::tagging::TaggingMarkerConfig::new(checkpoint).is_err() {
            anyhow::bail!(
                "oneironer.provider = \"endpoint\" requires oneironer.checkpoint_sha16, 16 lowercase hex digits"
            );
        }
        if self.label_count.is_none_or(|count| count == 0) {
            anyhow::bail!(
                "oneironer.provider = \"endpoint\" requires oneironer.label_count, the number of labels the tagger reports"
            );
        }
        // A zero first retry delay would let one refused answer be claimed
        // and sent again with no wait between passes.
        if self.timeout_ms == 0
            || self.batch_size == 0
            || self.idle_interval_ms == 0
            || self.retry_backoff_secs == 0
        {
            anyhow::bail!(
                "oneironer.timeout_ms, batch_size, idle_interval_ms and retry_backoff_secs must be greater than zero"
            );
        }
        if self.max_retry_backoff_secs < self.retry_backoff_secs {
            anyhow::bail!("oneironer.max_retry_backoff_secs must be at least retry_backoff_secs");
        }
        Ok(())
    }
}

fn registry_type_byte(kind: &str) -> Option<u8> {
    oneiron::registry::ENTITY_TYPE_REGISTRY
        .iter()
        .find(|entry| entry.kind == kind)
        .map(|entry| entry.type_byte)
}

/// One layer's contribution to the section.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct OneironerConfigOverride {
    pub provider: Option<OneironerProvider>,
    pub mode: Option<OneironerMode>,
    pub url: Option<String>,
    pub checkpoint_sha16: Option<String>,
    pub label_count: Option<u32>,
    pub labels: Option<BTreeMap<String, String>>,
    pub timeout_ms: Option<u64>,
    pub batch_size: Option<usize>,
    pub idle_interval_ms: Option<u64>,
    pub retry_backoff_secs: Option<u64>,
    pub max_retry_backoff_secs: Option<u64>,
    pub live_window_tokens: Option<u32>,
    pub trace_history_per_turn: Option<u32>,
    pub trace_history_max_age_secs: Option<u64>,
}

impl OneironerConfigOverride {
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }
}

/// `--oneironer-*` flags, flattened into the serve command.
#[derive(Args, Clone, Debug, Default)]
pub struct OneironerArgs {
    /// Tagger provider: `local`, `endpoint` or `none`.
    #[arg(long = "oneironer-provider")]
    pub oneironer_provider: Option<OneironerProvider>,
    /// `save` (the default) or `shadow`.
    #[arg(long = "oneironer-mode")]
    pub oneironer_mode: Option<OneironerMode>,
    /// Base URL of a loopback tagger server.
    #[arg(long = "oneironer-url")]
    pub oneironer_url: Option<String>,
    /// The checkpoint the tagger must report (16 lowercase hex digits).
    #[arg(long = "oneironer-checkpoint-sha16")]
    pub oneironer_checkpoint_sha16: Option<String>,
    /// How many labels the tagger must report.
    #[arg(long = "oneironer-label-count")]
    pub oneironer_label_count: Option<u32>,
    /// `LABEL=KIND` pairs, comma-separated; replaces the file's table.
    #[arg(long = "oneironer-labels", value_parser = parse_labels)]
    pub oneironer_labels: Option<BTreeMap<String, String>>,
    /// Request timeout per tagger call, in milliseconds.
    #[arg(long = "oneironer-timeout-ms")]
    pub oneironer_timeout_ms: Option<u64>,
}

impl From<&OneironerArgs> for OneironerConfigOverride {
    fn from(args: &OneironerArgs) -> Self {
        Self {
            provider: args.oneironer_provider,
            mode: args.oneironer_mode,
            url: args.oneironer_url.clone(),
            checkpoint_sha16: args.oneironer_checkpoint_sha16.clone(),
            label_count: args.oneironer_label_count,
            labels: args.oneironer_labels.clone(),
            timeout_ms: args.oneironer_timeout_ms,
            ..Self::default()
        }
    }
}

/// `LABEL=KIND,LABEL=KIND`.
fn parse_labels(value: &str) -> Result<BTreeMap<String, String>, String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|pair| !pair.is_empty())
        .map(|pair| {
            pair.split_once('=')
                .map(|(label, kind)| (label.trim().to_owned(), kind.trim().to_owned()))
                .ok_or_else(|| format!("oneironer label {pair:?} is not LABEL=KIND"))
        })
        .collect()
}

/// Reads the `ONEIRON_ONEIRONER_*` layer.
pub(super) fn lookup_oneironer_override(
    lookup: &mut impl FnMut(&str) -> Option<String>,
) -> anyhow::Result<Option<OneironerConfigOverride>> {
    let over = OneironerConfigOverride {
        provider: lookup_parse(lookup, "ONEIRON_ONEIRONER_PROVIDER")?,
        mode: lookup_parse(lookup, "ONEIRON_ONEIRONER_MODE")?,
        url: lookup("ONEIRON_ONEIRONER_URL"),
        checkpoint_sha16: lookup("ONEIRON_ONEIRONER_CHECKPOINT_SHA16"),
        label_count: lookup_parse(lookup, "ONEIRON_ONEIRONER_LABEL_COUNT")?,
        labels: lookup("ONEIRON_ONEIRONER_LABELS")
            .map(|value| parse_labels(&value).map_err(anyhow::Error::msg))
            .transpose()?,
        timeout_ms: lookup_parse(lookup, "ONEIRON_ONEIRONER_TIMEOUT_MS")?,
        batch_size: lookup_parse(lookup, "ONEIRON_ONEIRONER_BATCH_SIZE")?,
        idle_interval_ms: lookup_parse(lookup, "ONEIRON_ONEIRONER_IDLE_INTERVAL_MS")?,
        retry_backoff_secs: lookup_parse(lookup, "ONEIRON_ONEIRONER_RETRY_BACKOFF_SECS")?,
        max_retry_backoff_secs: lookup_parse(lookup, "ONEIRON_ONEIRONER_MAX_RETRY_BACKOFF_SECS")?,
        live_window_tokens: lookup_parse(lookup, "ONEIRON_ONEIRONER_LIVE_WINDOW_TOKENS")?,
        trace_history_per_turn: lookup_parse(lookup, "ONEIRON_ONEIRONER_TRACE_HISTORY_PER_TURN")?,
        trace_history_max_age_secs: lookup_parse(
            lookup,
            "ONEIRON_ONEIRONER_TRACE_HISTORY_MAX_AGE_SECS",
        )?,
    };
    Ok((!over.is_empty()).then_some(over))
}
