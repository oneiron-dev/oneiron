//! The `[oneironer]` section: the tagger slot's provider, mode, endpoint
//! identity, native runtime and label table.
//!
//! Opt-in like `[embedder]`: a server whose configuration never names the
//! section tags nothing and commits no tagging marker. Naming it selects a
//! provider, defaulting to the in-process local one (ARCH-0036: extraction
//! defaults to the device). Local models load a hash-bound artifact bundle.
//! A host may keep several local bundles as named tiers
//! (`[oneironer.tiers.<label>]`) and serve the one `tier` names.

use std::collections::BTreeMap;
use std::fmt;
use std::path::PathBuf;
use std::str::FromStr;

use clap::Args;
use serde::Deserialize;

use super::EmbedderDevice;
use super::lookup::lookup_parse;
use super::models::RequestCodec;

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
    /// In-process on this machine, using the configured native runtime.
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

/// Native inference runtime. Endpoint providers keep their own runtime.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum OneironerRuntime {
    #[default]
    Candle,
}

impl OneironerRuntime {
    pub const fn as_str(self) -> &'static str {
        "candle"
    }
}

impl FromStr for OneironerRuntime {
    type Err = String;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "candle" => Ok(Self::Candle),
            _ => Err("oneironer runtime must be candle".to_owned()),
        }
    }
}

/// Architecture selection is checked against the bundle's config.json.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum OneironerBackbone {
    #[default]
    Auto,
    Gte,
    Bert,
}

impl FromStr for OneironerBackbone {
    type Err = String;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "auto" => Ok(Self::Auto),
            "gte" => Ok(Self::Gte),
            "bert" => Ok(Self::Bert),
            _ => Err("oneironer backbone must be auto, gte or bert".to_owned()),
        }
    }
}

/// What the slot does with a checked answer.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum OneironerMode {
    /// A vault with a tagger saves its tags (owner ruling 2026-09-29).
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

/// One named local tagger candidate, `[oneironer.tiers.<label>]`: a bundle
/// and its identity. The label is data (`tiny`, `medium`, ...), never an
/// engine constant. Which candidate wins is measured outside the engine and
/// bound by the vault's manifest (ARCH-0036: the size ladder is retired and
/// the served tagger is a manifest row); `TaggerSlot::selected_by` holds the
/// host to that binding.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct OneironerTier {
    /// Directory containing the bundle's oneironer.json.
    pub model_dir: PathBuf,
    /// The bundle's checkpoint, as `checkpoint_sha16` above.
    pub checkpoint_sha16: String,
    /// The bundle's stack, when pinned, as `stack_sha16` above.
    #[serde(default)]
    pub stack_sha16: Option<String>,
    /// How many labels the bundle reports.
    pub label_count: u32,
    /// The bundle's own window ceiling, when it differs from the section's.
    #[serde(default)]
    pub max_input_tokens: Option<usize>,
}

/// Fully resolved `[oneironer]` section.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OneironerConfig {
    pub provider: OneironerProvider,
    pub mode: OneironerMode,
    /// Directory containing the native model's oneironer.json artifact manifest.
    pub model_dir: Option<PathBuf>,
    pub runtime: OneironerRuntime,
    pub backbone: OneironerBackbone,
    /// The local tagger's engine device. `auto`, the default, serves the
    /// fastest engine this machine runs that clears the bundle's parity bar,
    /// or the built-in CPU engine when the bundle ships no reference; a named
    /// device is the user's pick and must run here (`oneironer::engines`).
    pub device: EmbedderDevice,
    /// Native window ceiling, including context and special tokens. A current
    /// turn beyond it fails rather than silently saving a truncated tag set.
    pub max_input_tokens: usize,
    /// The named tier this host serves. Naming one takes the bundle and its
    /// identity from its row in `tiers`, over the section's own keys.
    pub tier: Option<String>,
    /// Named local tagger candidates, by label.
    pub tiers: BTreeMap<String, OneironerTier>,
    /// Base URL of the tagger server; the slot appends `/v1/model` and
    /// `/v1/extract`. Loopback only in this build.
    pub url: Option<String>,
    /// The codec the tagger decodes request bodies in (`"zstd"` or
    /// `"gzip"`): an extract body of 16 KiB or more goes in it when that is
    /// smaller (OF-604). Unset sends plain.
    pub request_compression: Option<RequestCodec>,
    /// The checkpoint the tagger must report: 16 lowercase hex digits of the
    /// SHA-256 of its weights. Also half of every marker's dedupe key.
    pub checkpoint_sha16: Option<String>,
    /// The served stack the tagger must report, when pinned: 16 lowercase
    /// hex digits of the SHA-256 of its stack card, which names the trunk
    /// and every head. Pinned, it joins the checkpoint in every marker's
    /// dedupe key, so a head swap owes every turn a new pass. Unpinned, any
    /// stack serving the checkpoint is accepted, and each answer's stack
    /// still enters its tags' derivation envelope.
    pub stack_sha16: Option<String>,
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
            model_dir: None,
            runtime: OneironerRuntime::default(),
            backbone: OneironerBackbone::default(),
            device: EmbedderDevice::Auto,
            max_input_tokens: 2048,
            tier: None,
            tiers: BTreeMap::new(),
            url: None,
            request_compression: None,
            checkpoint_sha16: None,
            stack_sha16: None,
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
    /// Both native and endpoint providers arm the same marker/save path.
    pub fn marker_checkpoint(&self) -> Option<&str> {
        self.is_active()
            .then_some(self.checkpoint_sha16.as_deref())
            .flatten()
    }

    /// The vault's marker configuration, when markers are on: the checkpoint
    /// and pinned stack, the live window, the trace history, the mode and the
    /// label table.
    pub fn marker_config(&self) -> Option<oneiron::tagging::TaggingMarkerConfig> {
        let checkpoint = self.marker_checkpoint()?;
        Some(oneiron::tagging::TaggingMarkerConfig {
            checkpoint: checkpoint.to_owned(),
            stack: self.stack_sha16.clone(),
            live_window_tokens: self.live_window_tokens,
            trace_history: self.trace_history(),
            mode: match self.mode {
                OneironerMode::Save => oneiron::tagging::TaggingMode::Save,
                OneironerMode::Shadow => oneiron::tagging::TaggingMode::Shadow,
            },
            labels: self.label_kinds(),
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
        if over.model_dir.is_some() {
            self.model_dir = over.model_dir;
        }
        if let Some(value) = over.runtime {
            self.runtime = value;
        }
        if let Some(value) = over.backbone {
            self.backbone = value;
        }
        if let Some(value) = over.device {
            self.device = value;
        }
        if let Some(value) = over.max_input_tokens {
            self.max_input_tokens = value;
        }
        if over.url.is_some() {
            self.url = over.url;
        }
        if over.request_compression.is_some() {
            self.request_compression = over.request_compression;
        }
        if over.checkpoint_sha16.is_some() {
            self.checkpoint_sha16 = over.checkpoint_sha16;
        }
        if over.stack_sha16.is_some() {
            self.stack_sha16 = over.stack_sha16;
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
        // Last, so a layer that names a tier serves its row's bundle.
        let reselect = over.tier.is_some() || over.tiers.is_some();
        if over.tier.is_some() {
            self.tier = over.tier;
        }
        if let Some(tiers) = over.tiers {
            self.tiers = tiers;
        }
        if reselect {
            self.select_tier();
        }
    }

    /// Takes the named tier's bundle and identity onto the section's keys.
    fn select_tier(&mut self) {
        let Some(row) = self
            .tier
            .as_ref()
            .and_then(|tier| self.tiers.get(tier))
            .cloned()
        else {
            return;
        };
        self.model_dir = Some(row.model_dir);
        self.checkpoint_sha16 = Some(row.checkpoint_sha16);
        self.stack_sha16 = row.stack_sha16;
        self.label_count = Some(row.label_count);
        if let Some(cap) = row.max_input_tokens {
            self.max_input_tokens = cap;
        }
    }

    /// The configured tier whose bundle serves `checkpoint`, if any.
    pub fn tier_serving(&self, checkpoint: &str) -> Option<&str> {
        self.tiers
            .iter()
            .find(|(_, row)| row.checkpoint_sha16 == checkpoint)
            .map(|(label, _)| label.as_str())
    }

    /// Refuses a section that cannot produce a working native or endpoint slot.
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
            let Some(byte) = registry_type_byte(kind) else {
                anyhow::bail!("oneironer.labels maps a label to unknown entity kind {kind:?}");
            };
            if !oneiron::tagging::label_kind_admitted(byte) {
                anyhow::bail!(
                    "oneironer.labels maps a label to {kind}, a kind with no identity key; leave the label out to keep it a tag"
                );
            }
        }
        for (label, row) in &self.tiers {
            if label.is_empty() || label.len() > MAX_LABEL_BYTES {
                anyhow::bail!("oneironer.tiers labels must be 1 to 64 bytes");
            }
            if row.model_dir.as_os_str().is_empty()
                || oneiron::tagging::TaggingMarkerConfig::new(&row.checkpoint_sha16).is_err()
                || row.label_count == 0
            {
                anyhow::bail!(
                    "oneironer.tiers.{label} requires model_dir, checkpoint_sha16 (16 lowercase hex digits) and a nonzero label_count"
                );
            }
        }
        if let Some(tier) = &self.tier {
            if !self.tiers.contains_key(tier) {
                anyhow::bail!("oneironer.tier = {tier:?} names no [oneironer.tiers] row");
            }
            if self.provider == OneironerProvider::Endpoint {
                anyhow::bail!(
                    "oneironer.tier selects a local bundle; it requires provider = \"local\""
                );
            }
        }
        if !self.is_active() {
            return Ok(());
        }
        if self.provider == OneironerProvider::Local {
            if self
                .model_dir
                .as_ref()
                .is_none_or(|dir| dir.as_os_str().is_empty())
            {
                anyhow::bail!("local oneironer requires oneironer.model_dir");
            }
            if self.max_input_tokens == 0 {
                anyhow::bail!("oneironer.max_input_tokens must be greater than zero");
            }
        }
        if self.provider == OneironerProvider::Endpoint
            && self.url.as_deref().unwrap_or_default().trim().is_empty()
        {
            anyhow::bail!(
                "oneironer.provider = \"endpoint\" requires oneironer.url (--oneironer-url / ONEIRON_ONEIRONER_URL)"
            );
        }
        let checkpoint = self.checkpoint_sha16.as_deref().unwrap_or_default();
        if oneiron::tagging::TaggingMarkerConfig::new(checkpoint).is_err() {
            anyhow::bail!("oneironer requires oneironer.checkpoint_sha16, 16 lowercase hex digits");
        }
        if self
            .stack_sha16
            .as_deref()
            .is_some_and(|stack| oneiron::tagging::TaggingMarkerConfig::new(stack).is_err())
        {
            anyhow::bail!("oneironer.stack_sha16 must be 16 lowercase hex digits");
        }
        if self.label_count.is_none_or(|count| count == 0) {
            anyhow::bail!(
                "oneironer requires oneironer.label_count, the number of labels the tagger reports"
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
    pub model_dir: Option<PathBuf>,
    pub runtime: Option<OneironerRuntime>,
    pub backbone: Option<OneironerBackbone>,
    pub device: Option<EmbedderDevice>,
    pub max_input_tokens: Option<usize>,
    pub tier: Option<String>,
    pub tiers: Option<BTreeMap<String, OneironerTier>>,
    pub url: Option<String>,
    pub request_compression: Option<RequestCodec>,
    pub checkpoint_sha16: Option<String>,
    pub stack_sha16: Option<String>,
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
    /// Local artifact bundle directory.
    #[arg(long = "oneironer-model-dir")]
    pub oneironer_model_dir: Option<PathBuf>,
    /// Native runtime: candle.
    #[arg(long = "oneironer-runtime")]
    pub oneironer_runtime: Option<OneironerRuntime>,
    /// Backbone: auto (from config.json), gte or bert.
    #[arg(long = "oneironer-backbone")]
    pub oneironer_backbone: Option<OneironerBackbone>,
    /// Native device: cpu, metal, cuda or auto.
    #[arg(long = "oneironer-device")]
    pub oneironer_device: Option<EmbedderDevice>,
    /// Native window ceiling, including context and special tokens.
    #[arg(long = "oneironer-max-input-tokens")]
    pub oneironer_max_input_tokens: Option<usize>,
    /// The named tier to serve, from the file's `[oneironer.tiers]`.
    #[arg(long = "oneironer-tier")]
    pub oneironer_tier: Option<String>,
    /// Base URL of a loopback tagger server.
    #[arg(long = "oneironer-url")]
    pub oneironer_url: Option<String>,
    /// The checkpoint the tagger must report (16 lowercase hex digits).
    #[arg(long = "oneironer-checkpoint-sha16")]
    pub oneironer_checkpoint_sha16: Option<String>,
    /// The served stack the tagger must report (16 lowercase hex digits).
    #[arg(long = "oneironer-stack-sha16")]
    pub oneironer_stack_sha16: Option<String>,
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
            model_dir: args.oneironer_model_dir.clone(),
            runtime: args.oneironer_runtime,
            backbone: args.oneironer_backbone,
            device: args.oneironer_device,
            max_input_tokens: args.oneironer_max_input_tokens,
            tier: args.oneironer_tier.clone(),
            url: args.oneironer_url.clone(),
            checkpoint_sha16: args.oneironer_checkpoint_sha16.clone(),
            stack_sha16: args.oneironer_stack_sha16.clone(),
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
        model_dir: lookup("ONEIRON_ONEIRONER_MODEL_DIR").map(PathBuf::from),
        runtime: lookup_parse(lookup, "ONEIRON_ONEIRONER_RUNTIME")?,
        backbone: lookup_parse(lookup, "ONEIRON_ONEIRONER_BACKBONE")?,
        device: lookup_parse(lookup, "ONEIRON_ONEIRONER_DEVICE")?,
        max_input_tokens: lookup_parse(lookup, "ONEIRON_ONEIRONER_MAX_INPUT_TOKENS")?,
        tier: lookup("ONEIRON_ONEIRONER_TIER"),
        tiers: None,
        url: lookup("ONEIRON_ONEIRONER_URL"),
        request_compression: None,
        checkpoint_sha16: lookup("ONEIRON_ONEIRONER_CHECKPOINT_SHA16"),
        stack_sha16: lookup("ONEIRON_ONEIRONER_STACK_SHA16"),
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
