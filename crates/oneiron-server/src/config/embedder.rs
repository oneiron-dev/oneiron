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

use super::embedder_shape::{
    EmbedderAttention, EmbedderOutputQuantization, parse_attention, parse_output_quantization,
};
use super::lookup::{lookup_parse, lookup_path};

/// Embedding SPACE id of the default local model: the upstream weights and the
/// HF commit they were read at. Satisfies the vault's `org/name@revision`
/// grammar, so it is what `vault_meta` pins.
pub const DEFAULT_MODEL_ID: &str =
    "perplexity-ai/pplx-embed-v1-0.6b@2c4d510dd4a732063c31a0f70193e35067b51fd8";
/// Repository holding the default local model's official files.
pub const DEFAULT_LOCAL_REPO: &str = "perplexity-ai/pplx-embed-v1-0.6b";
/// Commit the default local artifacts are pinned to.
pub const DEFAULT_LOCAL_REVISION: &str = "2c4d510dd4a732063c31a0f70193e35067b51fd8";
/// Dimensionality of the default local model. It is MRL-trained, but no
/// `fast_dims` prefix has been measured, so the vault runs at full width.
pub const DEFAULT_DIMENSIONS: usize = 1024;

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
    /// The best device this build can reach: Metal, then CUDA, else CPU.
    #[default]
    Auto,
    Cpu,
    Metal,
    Cuda,
}

impl EmbedderDevice {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Cpu => "cpu",
            Self::Metal => "metal",
            Self::Cuda => "cuda",
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
            "cuda" => Ok(Self::Cuda),
            other => Err(format!(
                "unknown embedder device {other:?} (expected auto, cpu, metal or cuda)"
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
    /// A third-party endpoint, only behind a host egress predicate.
    ThirdParty,
}

impl EmbedderLocality {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::OnDevice => "on-device",
            Self::OwnerServer => "owner-server",
            Self::ThirdParty => "third-party",
        }
    }
}

impl FromStr for EmbedderLocality {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "on-device" => Ok(Self::OnDevice),
            "owner-server" => Ok(Self::OwnerServer),
            "third-party" => Ok(Self::ThirdParty),
            other => Err(format!(
                "unknown embedder locality {other:?} (expected on-device or owner-server)"
            )),
        }
    }
}

/// The vault's declared order for resolving auto-device policy layers.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum AutoDevicePrecedence {
    /// Every layer can only reorder or narrow the preceding layer.
    #[default]
    NestedNarrowing,
    /// The CLI holder can override the environment, but never the vault cap.
    VaultCappedHolderOverride,
}

impl FromStr for AutoDevicePrecedence {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "nested-narrowing" => Ok(Self::NestedNarrowing),
            "vault-capped-holder-override" => Ok(Self::VaultCappedHolderOverride),
            _ => Err(format!("invalid embedder.policy.precedence {value:?}")),
        }
    }
}

/// Vault-local policy-manifest contribution for automatic device selection.
/// The vault file owns precedence; environment and holder layers only supply
/// candidate lists. A named device is an explicit selection outside `auto`.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct LocalDevicePolicy {
    pub auto_devices: Option<Vec<EmbedderDevice>>,
    pub precedence: Option<AutoDevicePrecedence>,
}

fn shipped_device_policy() -> LocalDevicePolicy {
    let policy: LocalDevicePolicy = toml::from_str(include_str!("../../policy/embedder.toml"))
        .expect("shipped embedder device policy parses");
    assert!(
        policy.auto_devices.is_some(),
        "shipped auto_devices row exists"
    );
    assert!(policy.precedence.is_some(), "shipped precedence row exists");
    policy
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
    /// Vault-capped, ordered candidates for `device = "auto"`.
    pub auto_devices: Vec<EmbedderDevice>,
    /// The vault file's ceiling, preserved when environment narrows.
    pub vault_auto_devices: Vec<EmbedderDevice>,
    /// How the configured layers select the final automatic candidate list.
    pub auto_device_precedence: AutoDevicePrecedence,
    /// Threads the load-time quantisation spreads over. `0` means "as many as
    /// this machine has cores". It does not change the forward pass, whose
    /// parallelism is candle's own.
    pub threads: usize,
    /// Overrides the attention the checkpoint's `config.json` declares.
    /// Changing it on a filled vault changes its vector space; run
    /// `reembed --force`.
    pub attention: EmbedderAttention,
    /// What a `FlexibleQuantizer` module in the checkpoint's chain emits.
    /// Changing it on a filled vault changes its vector space; run
    /// `reembed --force`.
    pub output_quantization: EmbedderOutputQuantization,
}

impl Default for LocalEmbedderConfig {
    fn default() -> Self {
        let policy = shipped_device_policy();
        let auto_devices = policy
            .auto_devices
            .expect("shipped auto_devices row exists");
        Self {
            repo: DEFAULT_LOCAL_REPO.to_owned(),
            revision: DEFAULT_LOCAL_REVISION.to_owned(),
            quant: EmbedderQuant::default(),
            model_dir: None,
            models_dir: None,
            device: EmbedderDevice::default(),
            vault_auto_devices: auto_devices.clone(),
            auto_devices,
            auto_device_precedence: policy.precedence.expect("shipped precedence row exists"),
            threads: 0,
            attention: EmbedderAttention::default(),
            output_quantization: EmbedderOutputQuantization::default(),
        }
    }
}

/// Keys only the endpoint provider reads.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EndpointEmbedderConfig {
    /// Name of an environment variable; never the key value.
    pub api_key_env: Option<String>,
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
            api_key_env: None,
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
    pub remote: Option<super::remote_embedder::RemoteEmbedderConfig>,
    pub provider: EmbedderProvider,
    /// The vault's embedding space id. Every provider reports exactly this.
    pub model_id: String,
    pub dimensions: usize,
    /// Text prepended to a query and never to a document. Unset, the local
    /// provider takes the query prompt from the model's own
    /// `config_sentence_transformers.json`, and an endpoint sends queries raw.
    pub query_instruction: Option<String>,
    /// Names the prompt in the model's `config_sentence_transformers.json`
    /// that queries carry, for a model whose prompts are named by task rather
    /// than `query`. Local provider only; `query_instruction` wins over it.
    pub query_prompt_name: Option<String>,
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
            remote: None,
            model_id: DEFAULT_MODEL_ID.to_owned(),
            dimensions: DEFAULT_DIMENSIONS,
            query_instruction: None,
            query_prompt_name: None,
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

    pub(super) fn apply_override(
        &mut self,
        over: EmbedderConfigOverride,
        source: super::merge::ConfigLayer,
    ) -> anyhow::Result<()> {
        apply_common(self, &over);
        apply_local(&mut self.local, &over, source)?;
        apply_endpoint(&mut self.endpoint, &over);
        if over.remote.is_some() {
            self.remote = over.remote;
        }
        Ok(())
    }
}

fn apply_common(config: &mut EmbedderConfig, over: &EmbedderConfigOverride) {
    if let Some(value) = over.provider {
        config.provider = value;
    }
    if let Some(value) = over.model_id.clone() {
        // The space id names the weights that fill it, so a layer naming a space
        // and not its files means that space's own repository and commit. Files
        // named as well must name the same ones (`embedder_space`).
        if let Some((repo, revision)) = value.split_once('@') {
            config.local.repo = repo.to_owned();
            config.local.revision = revision.to_owned();
        }
        config.model_id = value;
    }
    if let Some(value) = over.dimensions {
        config.dimensions = value;
    }
    if let Some(value) = over.query_instruction.clone() {
        config.query_instruction = Some(value);
    }
    if let Some(value) = over.query_prompt_name.clone() {
        config.query_prompt_name = Some(value);
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

fn apply_local(
    local: &mut LocalEmbedderConfig,
    over: &EmbedderConfigOverride,
    source: super::merge::ConfigLayer,
) -> anyhow::Result<()> {
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
    if let Some(value) = over.attention {
        local.attention = value;
    }
    if let Some(value) = over.output_quantization {
        local.output_quantization = value;
    }
    if let Some(precedence) = over.policy.as_ref().and_then(|policy| policy.precedence) {
        if source != super::merge::ConfigLayer::Vault {
            anyhow::bail!("embedder.policy.precedence may only be set by the vault file");
        }
        local.auto_device_precedence = precedence;
    }
    if let Some(devices) = over
        .policy
        .as_ref()
        .and_then(|policy| policy.auto_devices.as_ref())
    {
        // The source order is the server's existing file → environment → CLI
        // layering. The vault policy row, not this resolver, chooses which
        // parent constrains the holder's last selection.
        let ceiling = if source == super::merge::ConfigLayer::Holder
            && local.auto_device_precedence == AutoDevicePrecedence::VaultCappedHolderOverride
        {
            &local.vault_auto_devices
        } else {
            &local.auto_devices
        };
        if devices.is_empty()
            || devices.iter().any(|device| {
                *device == EmbedderDevice::Auto
                    || !ceiling.contains(device)
                    || devices.iter().filter(|item| *item == device).count() != 1
            })
        {
            anyhow::bail!(
                "embedder.policy.auto_devices must be a non-empty, unique subset of the permitted parent candidates, excluding auto"
            );
        }
        if source == super::merge::ConfigLayer::Vault {
            local.vault_auto_devices.clone_from(devices);
        }
        local.auto_devices.clone_from(devices);
    }
    Ok(())
}

fn apply_endpoint(endpoint: &mut EndpointEmbedderConfig, over: &EmbedderConfigOverride) {
    if over.api_key_env.is_some() {
        endpoint.api_key_env.clone_from(&over.api_key_env);
    }
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
    pub remote: Option<super::remote_embedder::RemoteEmbedderConfig>,
    pub api_key_env: Option<String>,
    pub provider: Option<EmbedderProvider>,
    pub model_id: Option<String>,
    pub dimensions: Option<usize>,
    pub query_instruction: Option<String>,
    pub query_prompt_name: Option<String>,
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
    pub policy: Option<LocalDevicePolicy>,
    pub threads: Option<usize>,
    pub attention: Option<EmbedderAttention>,
    pub output_quantization: Option<EmbedderOutputQuantization>,
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
            remote,
            api_key_env,
            provider,
            model_id,
            dimensions,
            query_instruction,
            query_prompt_name,
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
            policy,
            threads,
            attention,
            output_quantization,
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
    /// Remote rung JSON (endpoint, model_key, locality, lease_ms, egress).
    #[arg(long = "embedder-remote", value_parser = parse_remote)]
    pub embedder_remote: Option<super::remote_embedder::RemoteEmbedderConfig>,
    /// Environment variable holding the endpoint key. Never pass the key itself.
    #[arg(long = "embedder-api-key-env")]
    pub embedder_api_key_env: Option<String>,
    /// Embedder provider: `local`, `endpoint` or `none`.
    #[arg(long = "embedder-provider", value_parser = parse_provider)]
    pub embedder_provider: Option<EmbedderProvider>,
    /// Embedding space id (`org/name@revision`) pinned into the vault.
    #[arg(long = "embedder-model-id")]
    pub embedder_model_id: Option<String>,
    /// Embedding dimensionality. Must equal the vault's `--dimensions`.
    #[arg(long = "embedder-dimensions")]
    pub embedder_dimensions: Option<usize>,
    /// Text prepended to query text only; overrides the model's own prompt.
    #[arg(long = "embedder-query-instruction")]
    pub embedder_query_instruction: Option<String>,
    /// Name of the model's own prompt that queries carry.
    #[arg(long = "embedder-query-prompt-name")]
    pub embedder_query_prompt_name: Option<String>,
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
    /// Local device: `auto`, `cpu`, `metal` or `cuda`.
    #[arg(long = "embedder-device", value_parser = parse_device)]
    pub embedder_device: Option<EmbedderDevice>,
    /// Vault-local automatic device policy: comma-separated candidates in
    /// preference order, e.g. `cuda,cpu`; a later layer may only narrow.
    #[arg(long = "embedder-auto-devices", value_delimiter = ',', value_parser = parse_device)]
    pub embedder_auto_devices: Vec<EmbedderDevice>,
    /// Threads the load-time quantisation spreads over; `0` means all cores.
    #[arg(long = "embedder-threads")]
    pub embedder_threads: Option<usize>,
    /// Local attention: `auto` (the model's own), `causal` or `bidirectional`.
    /// Changing it on a filled vault changes its vectors: run `reembed --force`.
    #[arg(long = "embedder-attention", value_parser = parse_attention)]
    pub embedder_attention: Option<EmbedderAttention>,
    /// What a quantizer module in the chain emits: `int8` or `binary`.
    /// Changing it on a filled vault changes its vectors: run `reembed --force`.
    #[arg(long = "embedder-output-quantization", value_parser = parse_output_quantization)]
    pub embedder_output_quantization: Option<EmbedderOutputQuantization>,
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

fn parse_remote(value: &str) -> Result<super::remote_embedder::RemoteEmbedderConfig, String> {
    serde_json::from_str(value).map_err(|_| "invalid remote embedder JSON".into())
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

fn parse_auto_devices(value: &str) -> Result<Vec<EmbedderDevice>, String> {
    value.split(',').map(str::trim).map(str::parse).collect()
}

fn parse_locality(value: &str) -> Result<EmbedderLocality, String> {
    value.parse()
}

impl From<&EmbedderArgs> for EmbedderConfigOverride {
    fn from(args: &EmbedderArgs) -> Self {
        Self {
            remote: args.embedder_remote.clone(),
            api_key_env: args.embedder_api_key_env.clone(),
            provider: args.embedder_provider,
            model_id: args.embedder_model_id.clone(),
            dimensions: args.embedder_dimensions,
            query_instruction: args.embedder_query_instruction.clone(),
            query_prompt_name: args.embedder_query_prompt_name.clone(),
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
            policy: (!args.embedder_auto_devices.is_empty()).then(|| LocalDevicePolicy {
                auto_devices: Some(args.embedder_auto_devices.clone()),
                precedence: None,
            }),
            threads: args.embedder_threads,
            attention: args.embedder_attention,
            output_quantization: args.embedder_output_quantization,
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
        remote: lookup("ONEIRON_EMBEDDER_REMOTE")
            .map(|value| parse_remote(&value).map_err(anyhow::Error::msg))
            .transpose()?,
        api_key_env: lookup("ONEIRON_EMBEDDER_API_KEY_ENV"),
        provider: lookup_parse(lookup, "ONEIRON_EMBEDDER_PROVIDER")?,
        model_id: lookup("ONEIRON_EMBEDDER_MODEL_ID"),
        dimensions: lookup_parse(lookup, "ONEIRON_EMBEDDER_DIMENSIONS")?,
        query_instruction: lookup("ONEIRON_EMBEDDER_QUERY_INSTRUCTION"),
        query_prompt_name: lookup("ONEIRON_EMBEDDER_QUERY_PROMPT_NAME"),
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
        policy: {
            let auto_devices = lookup("ONEIRON_EMBEDDER_AUTO_DEVICES")
                .map(|value| parse_auto_devices(&value))
                .transpose()
                .map_err(anyhow::Error::msg)?;
            let precedence = lookup_parse(lookup, "ONEIRON_EMBEDDER_POLICY_PRECEDENCE")?;
            (auto_devices.is_some() || precedence.is_some()).then_some(LocalDevicePolicy {
                auto_devices,
                precedence,
            })
        },
        threads: lookup_parse(lookup, "ONEIRON_EMBEDDER_THREADS")?,
        attention: lookup_parse(lookup, "ONEIRON_EMBEDDER_ATTENTION")?,
        output_quantization: lookup_parse(lookup, "ONEIRON_EMBEDDER_OUTPUT_QUANTIZATION")?,
        endpoint: lookup("ONEIRON_EMBEDDER_ENDPOINT"),
        model_key: lookup("ONEIRON_EMBEDDER_MODEL_KEY"),
        artifact: lookup("ONEIRON_EMBEDDER_ARTIFACT"),
        locality: lookup_parse(lookup, "ONEIRON_EMBEDDER_LOCALITY")?,
        timeout_ms: lookup_parse(lookup, "ONEIRON_EMBEDDER_TIMEOUT_MS")?,
    };
    Ok((!over.is_empty()).then_some(over))
}
