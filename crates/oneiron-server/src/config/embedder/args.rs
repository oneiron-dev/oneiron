//! The `[embedder]` section's flag and environment layers:
//! `--embedder-*` and `ONEIRON_EMBEDDER_*`.

use std::path::PathBuf;

use clap::Args;

use super::{
    EmbedderConfigOverride, EmbedderDevice, EmbedderLocality, EmbedderProvider, EmbedderQuant,
    LocalDevicePolicy,
};
use crate::config::embedder_shape::{
    EmbedderAttention, EmbedderOutputQuantization, parse_attention, parse_output_quantization,
};
use crate::config::lookup::{lookup_parse, lookup_path};

/// `--embedder-*` flags, flattened into the serve command.
#[derive(Args, Clone, Debug, Default)]
pub struct EmbedderArgs {
    /// Remote rung JSON (endpoint, model_key, locality, lease_ms, egress).
    #[arg(long = "embedder-remote", value_parser = parse_remote)]
    pub embedder_remote: Option<crate::config::remote_embedder::RemoteEmbedderConfig>,
    /// Environment variable holding the endpoint key. Never pass the key itself.
    #[arg(long = "embedder-api-key-env")]
    pub embedder_api_key_env: Option<String>,
    /// Vault secret holding the endpoint key, sent through the credential
    /// broker. Never pass the key itself.
    #[arg(long = "embedder-key-secret")]
    pub embedder_key_secret: Option<String>,
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
    /// On a filled vault a change is refused at open; `reembed` migrates it.
    #[arg(long = "embedder-attention", value_parser = parse_attention)]
    pub embedder_attention: Option<EmbedderAttention>,
    /// What a quantizer module in the chain emits: `int8` or `binary`.
    /// On a filled vault a change is refused at open; `reembed` migrates it.
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

fn parse_remote(
    value: &str,
) -> Result<crate::config::remote_embedder::RemoteEmbedderConfig, String> {
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
            key_secret: args.embedder_key_secret.clone(),
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

/// Reads the `ONEIRON_EMBEDDER_*` layer.
///
/// Every key is optional and none of them has a default here: the layer only
/// says what the environment said, so an unset environment leaves the section
/// absent and the server at rung 0.
pub(in crate::config) fn lookup_embedder_override(
    lookup: &mut impl FnMut(&str) -> Option<String>,
) -> anyhow::Result<Option<EmbedderConfigOverride>> {
    let over = EmbedderConfigOverride {
        remote: lookup("ONEIRON_EMBEDDER_REMOTE")
            .map(|value| parse_remote(&value).map_err(anyhow::Error::msg))
            .transpose()?,
        api_key_env: lookup("ONEIRON_EMBEDDER_API_KEY_ENV"),
        key_secret: lookup("ONEIRON_EMBEDDER_KEY_SECRET"),
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
