//! The `[embedder]` section: provider selection and the keys each provider reads.
//!
//! The section is opt-in. A server whose configuration never mentions an
//! embedder keeps the posture it has always had — rung 0, no worker, vectors
//! supplied by the client — so adding this ticket changes no existing
//! deployment. Naming the section at all selects a provider, defaulting to the
//! in-process local one.

use std::fmt;
use std::path::PathBuf;
use std::str::FromStr;

use clap::Args;
use serde::Deserialize;

use super::lookup::{lookup_parse, lookup_path};

/// Embedding SPACE id of the default local model: the upstream weights and the
/// HF commit they were read at. Satisfies the vault's `org/name@revision`
/// grammar, so it is what `vault_meta` pins.
pub const DEFAULT_MODEL_ID: &str =
    "microsoft/harrier-oss-v1-0.6b@f9b9dc8d367d443f2479d27aa5d8d2850c0774ee";
/// Repository holding the default local model's official files.
pub const DEFAULT_LOCAL_REPO: &str = "microsoft/harrier-oss-v1-0.6b";
/// Commit the default local artifacts are pinned to.
pub const DEFAULT_LOCAL_REVISION: &str = "f9b9dc8d367d443f2479d27aa5d8d2850c0774ee";
/// Dimensionality of the default local model. No MRL, so no `fast_dims`.
pub const DEFAULT_DIMENSIONS: usize = 1024;
/// Instruction prepended to a QUERY and never to a document. The model's own
/// asymmetry: documents are embedded raw.
pub const DEFAULT_QUERY_INSTRUCTION: &str =
    "Instruct: Given a question, retrieve passages that answer it\nQuery: ";

const DEFAULT_BATCH_SIZE: usize = 32;
const DEFAULT_LEASE_MS: u64 = 30_000;
const DEFAULT_MAX_INPUT_TOKENS: usize = 4_096;
const DEFAULT_IDLE_INTERVAL_MS: u64 = 15_000;
const DEFAULT_TIMEOUT_MS: u64 = 60_000;

/// Which embedder runs behind the slot.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum EmbedderProvider {
    /// In-process candle. Downloads the pinned model on first use.
    #[default]
    Local,
    /// Any OpenAI-compatible `/v1/embeddings` server.
    Endpoint,
    /// Rung 0: no worker, no query door. Today's behaviour, stated.
    None,
}

impl EmbedderProvider {
    /// Wire spelling, also what the semantic query door reports.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::Endpoint => "endpoint",
            Self::None => "none",
        }
    }
}

impl FromStr for EmbedderProvider {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "local" => Ok(Self::Local),
            "endpoint" => Ok(Self::Endpoint),
            "none" => Ok(Self::None),
            other => Err(format!(
                "unknown embedder provider {other:?} (expected local, endpoint or none)"
            )),
        }
    }
}

/// Weight precision the local provider loads at.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum EmbedderQuant {
    /// Quantise every projection to Q8_0 at load. Runs on every device.
    #[default]
    #[serde(rename = "q8_0")]
    Q8_0,
    /// Keep the official bf16 weights. GPU only — candle's CPU backend has no
    /// bf16 matmul worth the name, so Q8_0 is the CPU path.
    None,
}

impl EmbedderQuant {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Q8_0 => "q8_0",
            Self::None => "none",
        }
    }
}

impl FromStr for EmbedderQuant {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "q8_0" => Ok(Self::Q8_0),
            "none" => Ok(Self::None),
            other => Err(format!(
                "unknown embedder quant {other:?} (expected q8_0 or none)"
            )),
        }
    }
}

/// Where the local provider runs the forward pass.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum EmbedderDevice {
    /// The best device this build can reach: Metal, else CPU.
    #[default]
    Auto,
    Cpu,
    Metal,
}

impl EmbedderDevice {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Cpu => "cpu",
            Self::Metal => "metal",
        }
    }
}

impl FromStr for EmbedderDevice {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "auto" => Ok(Self::Auto),
            "cpu" => Ok(Self::Cpu),
            "metal" => Ok(Self::Metal),
            other => Err(format!(
                "unknown embedder device {other:?} (expected auto, cpu or metal)"
            )),
        }
    }
}

/// Declared locality of an endpoint provider, recorded truthfully on every
/// vector it fills.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum EmbedderLocality {
    /// Same device as the vault.
    #[default]
    OnDevice,
    /// Infrastructure the vault owner controls.
    OwnerServer,
}

impl EmbedderLocality {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::OnDevice => "on-device",
            Self::OwnerServer => "owner-server",
        }
    }
}

impl FromStr for EmbedderLocality {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "on-device" => Ok(Self::OnDevice),
            "owner-server" => Ok(Self::OwnerServer),
            // Named on purpose rather than folded into the catch-all: a
            // third-party embedder is a real locality the engine models, and
            // this server has no egress predicate to gate it with yet.
            "third-party" => Err(
                "embedder locality third-party is rejected until an egress predicate is wired"
                    .to_owned(),
            ),
            other => Err(format!(
                "unknown embedder locality {other:?} (expected on-device or owner-server)"
            )),
        }
    }
}

/// Keys only the local provider reads.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalEmbedderConfig {
    pub repo: String,
    pub revision: String,
    pub quant: EmbedderQuant,
    /// A directory already holding the model's files. Set it and nothing is
    /// downloaded — the offline-host door.
    pub model_dir: Option<PathBuf>,
    /// Root the downloaded artifacts live under. Defaults to the XDG data dir.
    pub models_dir: Option<PathBuf>,
    pub device: EmbedderDevice,
    /// Threads the load-time quantisation spreads over. `0` means "as many as
    /// this machine has cores". It does not change the forward pass, whose
    /// parallelism is candle's own.
    pub threads: usize,
}

impl Default for LocalEmbedderConfig {
    fn default() -> Self {
        Self {
            repo: DEFAULT_LOCAL_REPO.to_owned(),
            revision: DEFAULT_LOCAL_REVISION.to_owned(),
            quant: EmbedderQuant::default(),
            model_dir: None,
            models_dir: None,
            device: EmbedderDevice::default(),
            threads: 0,
        }
    }
}

/// Keys only the endpoint provider reads.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EndpointEmbedderConfig {
    /// Base URL of an OpenAI-compatible server, e.g. `http://127.0.0.1:1234/v1`.
    pub endpoint: Option<String>,
    /// Model name the remote server answers to.
    pub model_key: Option<String>,
    /// Provenance of the artifact the remote actually serves. Logged, never
    /// verified: the server cannot see what the remote loaded.
    pub artifact: Option<String>,
    pub locality: EmbedderLocality,
    pub timeout_ms: u64,
}

impl Default for EndpointEmbedderConfig {
    fn default() -> Self {
        Self {
            endpoint: None,
            model_key: None,
            artifact: None,
            locality: EmbedderLocality::default(),
            // A derived `Default` would put zero here, and a zero request
            // timeout means every request is already late: reqwest reports
            // `TimedOut` before it opens the socket.
            timeout_ms: DEFAULT_TIMEOUT_MS,
        }
    }
}

/// Fully resolved `[embedder]` section.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EmbedderConfig {
    pub provider: EmbedderProvider,
    /// The vault's embedding space id. Every provider reports exactly this.
    pub model_id: String,
    pub dimensions: usize,
    pub query_instruction: String,
    pub batch_size: usize,
    pub lease_ms: u64,
    pub max_input_tokens: usize,
    pub idle_interval_ms: u64,
    pub local: LocalEmbedderConfig,
    pub endpoint: EndpointEmbedderConfig,
}

impl Default for EmbedderConfig {
    fn default() -> Self {
        Self {
            provider: EmbedderProvider::default(),
            model_id: DEFAULT_MODEL_ID.to_owned(),
            dimensions: DEFAULT_DIMENSIONS,
            query_instruction: DEFAULT_QUERY_INSTRUCTION.to_owned(),
            batch_size: DEFAULT_BATCH_SIZE,
            lease_ms: DEFAULT_LEASE_MS,
            max_input_tokens: DEFAULT_MAX_INPUT_TOKENS,
            idle_interval_ms: DEFAULT_IDLE_INTERVAL_MS,
            local: LocalEmbedderConfig::default(),
            endpoint: EndpointEmbedderConfig::default(),
        }
    }
}

impl EmbedderConfig {
    /// Whether this section asks for a worker at all.
    pub const fn is_active(&self) -> bool {
        !matches!(self.provider, EmbedderProvider::None)
    }

    pub(super) fn apply_override(&mut self, over: EmbedderConfigOverride) {
        apply_common(self, &over);
        apply_local(&mut self.local, &over);
        apply_endpoint(&mut self.endpoint, &over);
    }
}

fn apply_common(config: &mut EmbedderConfig, over: &EmbedderConfigOverride) {
    if let Some(value) = over.provider {
        config.provider = value;
    }
    if let Some(value) = over.model_id.clone() {
        config.model_id = value;
    }
    if let Some(value) = over.dimensions {
        config.dimensions = value;
    }
    if let Some(value) = over.query_instruction.clone() {
        config.query_instruction = value;
    }
    if let Some(value) = over.batch_size {
        config.batch_size = value;
    }
    if let Some(value) = over.lease_ms {
        config.lease_ms = value;
    }
    if let Some(value) = over.max_input_tokens {
        config.max_input_tokens = value;
    }
    if let Some(value) = over.idle_interval_ms {
        config.idle_interval_ms = value;
    }
}

fn apply_local(local: &mut LocalEmbedderConfig, over: &EmbedderConfigOverride) {
    if let Some(value) = over.repo.clone() {
        local.repo = value;
    }
    if let Some(value) = over.revision.clone() {
        local.revision = value;
    }
    if let Some(value) = over.quant {
        local.quant = value;
    }
    if let Some(value) = over.model_dir.clone() {
        local.model_dir = Some(value);
    }
    if let Some(value) = over.models_dir.clone() {
        local.models_dir = Some(value);
    }
    if let Some(value) = over.device {
        local.device = value;
    }
    if let Some(value) = over.threads {
        local.threads = value;
    }
}

fn apply_endpoint(endpoint: &mut EndpointEmbedderConfig, over: &EmbedderConfigOverride) {
    if let Some(value) = over.endpoint.clone() {
        endpoint.endpoint = Some(value);
    }
    if let Some(value) = over.model_key.clone() {
        endpoint.model_key = Some(value);
    }
    if let Some(value) = over.artifact.clone() {
        endpoint.artifact = Some(value);
    }
    if let Some(value) = over.locality {
        endpoint.locality = value;
    }
    if let Some(value) = over.timeout_ms {
        endpoint.timeout_ms = value;
    }
}

/// One layer's contribution to the section. Flat rather than nested so the
/// TOML table, the environment keys and the flags carry the same names.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct EmbedderConfigOverride {
    pub provider: Option<EmbedderProvider>,
    pub model_id: Option<String>,
    pub dimensions: Option<usize>,
    pub query_instruction: Option<String>,
    pub batch_size: Option<usize>,
    pub lease_ms: Option<u64>,
    pub max_input_tokens: Option<usize>,
    pub idle_interval_ms: Option<u64>,
    pub repo: Option<String>,
    pub revision: Option<String>,
    pub quant: Option<EmbedderQuant>,
    pub model_dir: Option<PathBuf>,
    pub models_dir: Option<PathBuf>,
    pub device: Option<EmbedderDevice>,
    pub threads: Option<usize>,
    pub endpoint: Option<String>,
    pub model_key: Option<String>,
    pub artifact: Option<String>,
    pub locality: Option<EmbedderLocality>,
    pub timeout_ms: Option<u64>,
}

impl EmbedderConfigOverride {
    /// Whether this layer said anything at all about the embedder.
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }

    /// Folds a higher-precedence layer over this one.
    pub fn merge(&mut self, higher: Self) {
        macro_rules! take {
            ($($field:ident),+ $(,)?) => {$(
                if higher.$field.is_some() {
                    self.$field = higher.$field;
                }
            )+};
        }
        take!(
            provider,
            model_id,
            dimensions,
            query_instruction,
            batch_size,
            lease_ms,
            max_input_tokens,
            idle_interval_ms,
            repo,
            revision,
            quant,
            model_dir,
            models_dir,
            device,
            threads,
            endpoint,
            model_key,
            artifact,
            locality,
            timeout_ms,
        );
    }
}

/// `--embedder-*` flags, flattened into the serve command.
#[derive(Args, Clone, Debug, Default)]
pub struct EmbedderArgs {
    /// Embedder provider: `local`, `endpoint` or `none`.
    #[arg(long = "embedder-provider", value_parser = parse_provider)]
    pub embedder_provider: Option<EmbedderProvider>,
    /// Embedding space id (`org/name@revision`) pinned into the vault.
    #[arg(long = "embedder-model-id")]
    pub embedder_model_id: Option<String>,
    /// Embedding dimensionality. Must equal the vault's `--dimensions`.
    #[arg(long = "embedder-dimensions")]
    pub embedder_dimensions: Option<usize>,
    /// Instruction prepended to query text only.
    #[arg(long = "embedder-query-instruction")]
    pub embedder_query_instruction: Option<String>,
    /// Rows embedded per reconciler pass.
    #[arg(long = "embedder-batch-size")]
    pub embedder_batch_size: Option<usize>,
    /// Pending-embedding lease window in milliseconds.
    #[arg(long = "embedder-lease-ms")]
    pub embedder_lease_ms: Option<u64>,
    /// Token cap per input; longer inputs lose tokens from the end.
    #[arg(long = "embedder-max-input-tokens")]
    pub embedder_max_input_tokens: Option<usize>,
    /// Idle sleep between empty reconciler passes, in milliseconds.
    #[arg(long = "embedder-idle-interval-ms")]
    pub embedder_idle_interval_ms: Option<u64>,
    /// Hugging Face repository holding the local model files.
    #[arg(long = "embedder-repo")]
    pub embedder_repo: Option<String>,
    /// Commit revision of that repository.
    #[arg(long = "embedder-revision")]
    pub embedder_revision: Option<String>,
    /// Local weight precision: `q8_0` or `none`.
    #[arg(long = "embedder-quant", value_parser = parse_quant)]
    pub embedder_quant: Option<EmbedderQuant>,
    /// Directory already holding the model files; skips every download.
    #[arg(long = "embedder-model-dir")]
    pub embedder_model_dir: Option<PathBuf>,
    /// Root directory downloaded models are stored under.
    #[arg(long = "embedder-models-dir")]
    pub embedder_models_dir: Option<PathBuf>,
    /// Local device: `auto`, `cpu` or `metal`.
    #[arg(long = "embedder-device", value_parser = parse_device)]
    pub embedder_device: Option<EmbedderDevice>,
    /// Threads the load-time quantisation spreads over; `0` means all cores.
    #[arg(long = "embedder-threads")]
    pub embedder_threads: Option<usize>,
    /// Base URL of an OpenAI-compatible embeddings server.
    #[arg(long = "embedder-endpoint")]
    pub embedder_endpoint: Option<String>,
    /// Model name the remote embeddings server answers to.
    #[arg(long = "embedder-model-key")]
    pub embedder_model_key: Option<String>,
    /// Provenance string for the artifact the remote serves.
    #[arg(long = "embedder-artifact")]
    pub embedder_artifact: Option<String>,
    /// Declared endpoint locality: `on-device` or `owner-server`.
    #[arg(long = "embedder-locality", value_parser = parse_locality)]
    pub embedder_locality: Option<EmbedderLocality>,
    /// Endpoint request timeout in milliseconds.
    #[arg(long = "embedder-timeout-ms")]
    pub embedder_timeout_ms: Option<u64>,
}

fn parse_provider(value: &str) -> Result<EmbedderProvider, String> {
    value.parse()
}

fn parse_quant(value: &str) -> Result<EmbedderQuant, String> {
    value.parse()
}

fn parse_device(value: &str) -> Result<EmbedderDevice, String> {
    value.parse()
}

fn parse_locality(value: &str) -> Result<EmbedderLocality, String> {
    value.parse()
}

impl From<&EmbedderArgs> for EmbedderConfigOverride {
    fn from(args: &EmbedderArgs) -> Self {
        Self {
            provider: args.embedder_provider,
            model_id: args.embedder_model_id.clone(),
            dimensions: args.embedder_dimensions,
            query_instruction: args.embedder_query_instruction.clone(),
            batch_size: args.embedder_batch_size,
            lease_ms: args.embedder_lease_ms,
            max_input_tokens: args.embedder_max_input_tokens,
            idle_interval_ms: args.embedder_idle_interval_ms,
            repo: args.embedder_repo.clone(),
            revision: args.embedder_revision.clone(),
            quant: args.embedder_quant,
            model_dir: args.embedder_model_dir.clone(),
            models_dir: args.embedder_models_dir.clone(),
            device: args.embedder_device,
            threads: args.embedder_threads,
            endpoint: args.embedder_endpoint.clone(),
            model_key: args.embedder_model_key.clone(),
            artifact: args.embedder_artifact.clone(),
            locality: args.embedder_locality,
            timeout_ms: args.embedder_timeout_ms,
        }
    }
}

impl fmt::Display for EmbedderProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Reads the `ONEIRON_EMBEDDER_*` layer.
///
/// Every key is optional and none of them has a default here: the layer only
/// says what the environment said, so an unset environment leaves the section
/// absent and the server at rung 0.
pub(super) fn lookup_embedder_override(
    lookup: &mut impl FnMut(&str) -> Option<String>,
) -> anyhow::Result<Option<EmbedderConfigOverride>> {
    let over = EmbedderConfigOverride {
        provider: lookup_parse(lookup, "ONEIRON_EMBEDDER_PROVIDER")?,
        model_id: lookup("ONEIRON_EMBEDDER_MODEL_ID"),
        dimensions: lookup_parse(lookup, "ONEIRON_EMBEDDER_DIMENSIONS")?,
        query_instruction: lookup("ONEIRON_EMBEDDER_QUERY_INSTRUCTION"),
        batch_size: lookup_parse(lookup, "ONEIRON_EMBEDDER_BATCH_SIZE")?,
        lease_ms: lookup_parse(lookup, "ONEIRON_EMBEDDER_LEASE_MS")?,
        max_input_tokens: lookup_parse(lookup, "ONEIRON_EMBEDDER_MAX_INPUT_TOKENS")?,
        idle_interval_ms: lookup_parse(lookup, "ONEIRON_EMBEDDER_IDLE_INTERVAL_MS")?,
        repo: lookup("ONEIRON_EMBEDDER_REPO"),
        revision: lookup("ONEIRON_EMBEDDER_REVISION"),
        quant: lookup_parse(lookup, "ONEIRON_EMBEDDER_QUANT")?,
        model_dir: lookup_path(lookup, "ONEIRON_EMBEDDER_MODEL_DIR"),
        models_dir: lookup_path(lookup, "ONEIRON_EMBEDDER_MODELS_DIR"),
        device: lookup_parse(lookup, "ONEIRON_EMBEDDER_DEVICE")?,
        threads: lookup_parse(lookup, "ONEIRON_EMBEDDER_THREADS")?,
        endpoint: lookup("ONEIRON_EMBEDDER_ENDPOINT"),
        model_key: lookup("ONEIRON_EMBEDDER_MODEL_KEY"),
        artifact: lookup("ONEIRON_EMBEDDER_ARTIFACT"),
        locality: lookup_parse(lookup, "ONEIRON_EMBEDDER_LOCALITY")?,
        timeout_ms: lookup_parse(lookup, "ONEIRON_EMBEDDER_TIMEOUT_MS")?,
    };
    Ok((!over.is_empty()).then_some(over))
}
