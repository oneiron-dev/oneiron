//! Layered merge: file, environment, and argv values into `ServeConfig`.

use std::collections::HashMap;
use std::fmt;
use std::path::{Path, PathBuf};

use anyhow::Context;
use oneiron::{HostingPrivacyPosture, SyncConfigField, SyncProtocolValidation};
use serde::Deserialize;

use super::backup::{BackupConfig, BackupConfigOverride, lookup_backup_override};
use super::embedder::{EmbedderConfig, EmbedderProvider};
use super::embedder::{EmbedderConfigOverride, lookup_embedder_override};
use super::failure_signals::{FailureSignalsConfigOverride, lookup_failure_signals_override};
use super::feedback::{FeedbackConfigOverride, lookup_feedback_override};
use super::import::ImportConfigOverride;
use super::keystore::{KeystoreConfigOverride, lookup_keystore_override};
use super::limits::LimitsConfigOverride;
use super::lookup::{
    DEFAULT_CONFIG_DIR, DEFAULT_CONFIG_FILE, expand_home, lookup_bool, lookup_list, lookup_parse,
    lookup_path, lookup_path_list, normalize_list, redacted_secret,
};
use super::models::{ModelsConfig, ModelsFile};
use super::oneironer::{OneironerConfig, OneironerConfigOverride, lookup_oneironer_override};
use super::recall::{RecallConfigOverride, lookup_recall_override};
use super::self_heal::SelfHealConfigOverride;
use super::serve_args::{ServeArgs, runtime_override_from_args};
use super::server_config::ServeConfig;
use super::skills::{SkillsConfigOverride, lookup_skills_override};
use super::trusted_proxy::parse_trusted_proxies;
use crate::runtime::{
    RuntimeConfigOverride, RuntimeMode, RuntimeProviderKind, RuntimeRole, RuntimeRoleTargetOverride,
};

use super::{
    BrowserConfig, DesktopConfig, DeviceSyncConfig, EmbeddingConfig, LineConfig, LinearConfig,
    MergeQueueCheckerConfig, NativeMailConfig, embedder, remote_embedder,
};

mod sections;
mod validation;

pub use self::sections::default_config_path;
pub(crate) use self::validation::settings_schema_keys;
use self::validation::{validate_embedder_config, validate_serve_config};

/// Environment-derived serve settings.
#[derive(Clone, Debug, Default)]
pub struct EnvConfig {
    pub config_path: Option<PathBuf>,
    values: PartialServeConfig,
}

pub fn resolve_serve_config(args: &ServeArgs) -> anyhow::Result<ServeConfig> {
    resolve_serve_config_with_sources(args, EnvConfig::from_process()?, default_config_path())
}

/// The `[backup]` settings alone: the config file's section, then the
/// environment, the way `resolve_serve_config` layers them. A command that
/// only reports on backups (`doctor`) uses this so a server setting it never
/// reads cannot stop it.
pub fn resolve_backup_config(args: &ServeArgs) -> anyhow::Result<BackupConfig> {
    let env_path = std::env::var_os("ONEIRON_CONFIG").map(PathBuf::from);
    let explicit = args.config.is_some() || env_path.is_some();
    let mut backup = BackupConfig::default();
    match args
        .config
        .clone()
        .or(env_path)
        .or_else(default_config_path)
    {
        Some(path) if path.exists() => {
            if let Some(over) = load_backup_section(&path)? {
                backup.apply_override(over);
            }
        }
        Some(path) if explicit => {
            anyhow::bail!("config file {} does not exist", path.display());
        }
        _ => {}
    }
    // The owner's settings file over it, as serve layers it (FIX 5016).
    if let Some(path) = &args.settings_file
        && let Some(over) = load_backup_section(path)?
    {
        backup.apply_override(over);
    }
    if let Some(over) = lookup_backup_override(&mut |key| std::env::var(key).ok())? {
        backup.apply_override(over);
    }
    backup.validate()?;
    Ok(backup)
}

/// The existing server configuration layers, from vault policy to holder.
/// Their order is structural; the embedder policy row chooses which parent
/// constrains the holder's automatic device candidates.
#[derive(Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
pub(super) enum ConfigLayer {
    Vault,
    Environment,
    Holder,
}

pub fn resolve_serve_config_with_sources(
    args: &ServeArgs,
    env: EnvConfig,
    default_config_path: Option<PathBuf>,
) -> anyhow::Result<ServeConfig> {
    let resolved = layer_serve_config(args, env, default_config_path)?;
    // Same-source or higher-precedence references remain for validation to
    // refuse rather than silently fixing a contradictory self-host request.
    validate_serve_config(&resolved)?;
    Ok(resolved)
}

/// The file, environment and flag layers merged, before the checks that
/// hold the result to one vault ([`resolve_serve_config_with_sources`]). A
/// command with no vault reads what a layered section says through this.
pub(crate) fn layer_serve_config(
    args: &ServeArgs,
    env: EnvConfig,
    default_config_path: Option<PathBuf>,
) -> anyhow::Result<ServeConfig> {
    let flag_values = PartialServeConfig::from(args);
    let config_path = args
        .config
        .clone()
        .or_else(|| env.config_path.clone())
        .or(default_config_path);
    let explicit_config = args.config.is_some() || env.config_path.is_some();
    let file_values = match config_path {
        Some(path) if path.exists() => load_file_config(&path)?,
        Some(path) if explicit_config => {
            anyhow::bail!("config file {} does not exist", path.display());
        }
        _ => PartialServeConfig::default(),
    };
    // The owner's settings file (`--settings-file`, FIX 5016), in the config
    // file's schema as a managed vault reads it: one more vault file layer,
    // over the config file and under the environment and the flags.
    let settings_values = args
        .settings_file
        .as_deref()
        .map(load_file_config)
        .transpose()?;

    let space_naming = super::embedder_space::SpaceNaming::of([
        file_values.embedder.as_ref(),
        settings_values
            .as_ref()
            .and_then(|values| values.embedder.as_ref()),
        env.values.embedder.as_ref(),
        flag_values.embedder.as_ref(),
    ]);
    let mut resolved = ServeConfig::default();
    let mut posture_source = None;
    let mut key_ref_source = None;
    for (source, values) in [
        (ConfigLayer::Vault, Some(file_values)),
        (ConfigLayer::Vault, settings_values),
        (ConfigLayer::Environment, Some(env.values)),
        (ConfigLayer::Holder, Some(flag_values)),
    ] {
        let Some(values) = values else {
            continue;
        };
        if values.privacy_posture.is_some() {
            posture_source = Some(source);
        }
        if values.hosted_kms_key_ref.is_some() {
            key_ref_source = Some(source);
        }
        values.apply_to(&mut resolved, source)?;
    }
    // Only the final posture may discard inherited custody, and only a blind
    // relay, which holds no key: a self-hosted vault keeps an inherited KMS
    // reference as its own key's custody. An intermediate relay layer can
    // still be overridden by a later hosted layer, which needs the
    // highest-precedence reference even when it came from the file.
    if resolved.privacy_posture == HostingPrivacyPosture::Relay
        && let (Some(posture_source), Some(key_ref_source)) = (posture_source, key_ref_source)
        && key_ref_source < posture_source
    {
        resolved.hosted_kms_key_ref = None;
    }
    if let Some(embedder) = resolved.embedder.as_mut() {
        super::embedder_space::settle_local_space(embedder, space_naming)?;
    }
    // The organ builds this server runs as first party, from argv alone
    // (FIX 7644): no file, settings file or environment layer names one.
    resolved.trusted_organ_builds = args.trusted_organ_builds.iter().cloned().collect();
    // `--voice-socket` names where the voice loop the layered
    // `[models.voice]` turns on listens, over its `socket` (FIX 5016), as
    // managed mode sets it on its settings file. With no voice configured it
    // names nothing.
    if let Some(socket) = &args.voice_socket
        && let Some(models) = resolved.models.as_mut()
    {
        models.voice.listen_on(socket)?;
    }
    Ok(resolved)
}

/// One `[embedder]` table settled onto `config` as [`layer_serve_config`]
/// settles the layered section: applied over the defaults as the vault file's
/// layer, its local space settled, then refused as serve refuses a section
/// that cannot make a working slot. A managed vault's settings file is the
/// one layer it has (FIX 777, [`settle_managed_settings`]).
pub(crate) fn settle_embedder_section(
    config: &mut ServeConfig,
    section: EmbedderConfigOverride,
) -> anyhow::Result<()> {
    let space_naming = super::embedder_space::SpaceNaming::of([Some(&section), None, None]);
    let mut embedder = EmbedderConfig::default();
    embedder.apply_override(section, ConfigLayer::Vault)?;
    super::embedder_space::settle_local_space(&mut embedder, space_naming)?;
    config.embedder = Some(embedder);
    validate_embedder_config(config)
}

/// A managed vault's settings file, which managed mode has already refused
/// leaf by leaf (`managed::settings`), settled once over the `config` it
/// built from argv: `table`, what it kept of the file at `path` whose text
/// is `raw`, read in the config file's schema, its `[models]` resolved
/// beside the file, applied as the vault file's layer, its `[embedder]`
/// settled as [`settle_embedder_section`] settles one, and the result
/// refused as serve refuses a config that cannot serve. No other layer is
/// read: no environment, no default config path. A table that does not read
/// names only the place in `raw` where it fails, never the value refused
/// (FIX 9477, 10687); the caller names the file.
pub(crate) fn settle_managed_settings(
    config: &mut ServeConfig,
    table: toml::Table,
    path: &Path,
    raw: &str,
) -> anyhow::Result<()> {
    // The deserializer's error names the value it refused, and the table
    // keeps no place in the file: it is dropped unread, and the file's own
    // text read again for the place.
    let mut file: FileServeConfig = toml::Value::Table(table)
        .try_into()
        .map_err(|_| super::locate_toml_failure::<FileServeConfig>(raw))?;
    let models = file
        .models
        .take()
        .map(|models| models.resolve(path.parent()))
        .transpose()
        .context("the settings file's [models]")?;
    let embedder = file.embedder.take();
    let mut values = PartialServeConfig::from(file);
    values.models = models;
    values.apply_to(config, ConfigLayer::Vault)?;
    if let Some(section) = embedder {
        settle_embedder_section(config, section).context("the settings file's [embedder]")?;
    }
    validate_serve_config(config)
}

/// The config file's `[backup]` table alone: a mistyped setting elsewhere in
/// the file does not stop it being read. A file that does not parse names
/// only itself and the place it failed (FIX 9477).
fn load_backup_section(path: &Path) -> anyhow::Result<Option<BackupConfigOverride>> {
    /// The file with every key but `[backup]` skipped unread.
    #[derive(Deserialize)]
    struct BackupOnly {
        backup: Option<BackupConfigOverride>,
    }
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("read config file {}", path.display()))?;
    let file: BackupOnly = super::parse_toml(path, &raw)?;
    Ok(file.backup)
}

/// The config file's layer. A file that does not parse names only itself
/// and the place it failed (FIX 9477).
fn load_file_config(path: &Path) -> anyhow::Result<PartialServeConfig> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("read config file {}", path.display()))?;
    let mut config: FileServeConfig = super::parse_toml(path, &raw)?;
    let models = config
        .models
        .take()
        .map(|models| models.resolve(path.parent()))
        .transpose()
        .with_context(|| format!("config file {}", path.display()))?;
    let mut values = PartialServeConfig::from(config);
    values.models = models;
    Ok(values)
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct FileServeConfig {
    vault_path: Option<PathBuf>,
    host: Option<String>,
    port: Option<u16>,
    artifact_port: Option<u16>,
    auth_secret: Option<String>,
    oauth_issuer: Option<String>,
    oauth_jwks_uri: Option<String>,
    oauth_resource_indicator: Option<String>,
    kit_bundle_public_urls: Option<Vec<String>>,
    allow_unauthenticated: Option<bool>,
    allowed_origins: Option<Vec<String>>,
    artifact_domains: Option<Vec<String>>,
    artifact_vault_name: Option<String>,
    trusted_proxies: Option<Vec<String>>,
    lease_vault_id: Option<u64>,
    dimensions: Option<usize>,
    fast_dims: Option<u16>,
    map_size: Option<usize>,
    log_level: Option<String>,
    dict_search_paths: Option<Vec<PathBuf>>,
    assistant_display_names: Option<Vec<String>>,
    default_window_count: Option<u8>,
    compaction_threshold_bytes: Option<u32>,
    compaction_throttle_secs: Option<u32>,
    bulk_chunk_size: Option<usize>,
    max_frame_size: Option<usize>,
    max_update_payload: Option<usize>,
    max_windows_per_connection: Option<usize>,
    max_messages_per_sec: Option<u32>,
    ephemeral_timeout_ms: Option<i64>,
    max_ephemeral_payload_bytes: Option<usize>,
    max_ephemeral_snapshot_bytes: Option<usize>,
    max_entity_blob: Option<usize>,
    max_lfs_object_bytes: Option<u64>,
    max_bulk_decompressed: Option<usize>,
    runtime: Option<RuntimeConfigOverride>,
    embedder: Option<EmbedderConfigOverride>,
    oneironer: Option<OneironerConfigOverride>,
    backup: Option<BackupConfigOverride>,
    feedback: Option<FeedbackConfigOverride>,
    failure_signals: Option<FailureSignalsConfigOverride>,
    self_heal: Option<SelfHealConfigOverride>,
    recall: Option<RecallConfigOverride>,
    skills: Option<SkillsConfigOverride>,
    keystore: Option<KeystoreConfigOverride>,
    limits: Option<LimitsConfigOverride>,
    import: Option<ImportConfigOverride>,
    models: Option<ModelsFile>,
    browser: Option<super::BrowserConfig>,
    desktop: Option<super::DesktopConfig>,
    merge_queue: Option<super::MergeQueueCheckerConfig>,
    gpu: Option<crate::runtime::GpuPoolConfig>,
    native_mail: Option<super::NativeMailConfig>,
    device_sync: Option<super::DeviceSyncConfig>,
    connectors: Option<std::collections::BTreeMap<String, super::ConnectorHostConfig>>,
    embedding: Option<super::EmbeddingConfig>,
    line: Option<super::LineConfig>,
    linear: Option<super::LinearConfig>,
    privacy_posture: Option<HostingPrivacyPosture>,
    failure_signal_export: Option<bool>,
    failure_signal_training: Option<bool>,
    hosted_kms_key_ref: Option<String>,
    maximum_tier: Option<bool>,
    device_class: Option<oneiron::authority::MachineDeviceClass>,
}

impl From<FileServeConfig> for PartialServeConfig {
    fn from(value: FileServeConfig) -> Self {
        Self {
            vault_path: value.vault_path,
            host: value.host,
            port: value.port,
            artifact_port: value.artifact_port,
            auth_secret: value.auth_secret,
            oauth_issuer: value.oauth_issuer,
            oauth_jwks_uri: value.oauth_jwks_uri,
            oauth_resource_indicator: value.oauth_resource_indicator,
            kit_bundle_public_urls: value.kit_bundle_public_urls,
            allow_unauthenticated: value.allow_unauthenticated,
            allowed_origins: value.allowed_origins,
            artifact_domains: value.artifact_domains,
            artifact_vault_name: value.artifact_vault_name,
            trusted_proxies: value.trusted_proxies,
            lease_vault_id: value.lease_vault_id,
            dimensions: value.dimensions,
            fast_dims: value.fast_dims,
            map_size: value.map_size,
            log_level: value.log_level,
            dict_search_paths: value.dict_search_paths,
            assistant_display_names: value.assistant_display_names,
            default_window_count: value.default_window_count,
            compaction_threshold_bytes: value.compaction_threshold_bytes,
            compaction_throttle_secs: value.compaction_throttle_secs,
            bulk_chunk_size: value.bulk_chunk_size,
            max_frame_size: value.max_frame_size,
            max_update_payload: value.max_update_payload,
            max_windows_per_connection: value.max_windows_per_connection,
            max_messages_per_sec: value.max_messages_per_sec,
            ephemeral_timeout_ms: value.ephemeral_timeout_ms,
            max_ephemeral_payload_bytes: value.max_ephemeral_payload_bytes,
            max_ephemeral_snapshot_bytes: value.max_ephemeral_snapshot_bytes,
            max_entity_blob: value.max_entity_blob,
            max_lfs_object_bytes: value.max_lfs_object_bytes,
            max_bulk_decompressed: value.max_bulk_decompressed,
            runtime: value.runtime,
            embedder: value.embedder,
            oneironer: value.oneironer,
            backup: value.backup,
            feedback: value.feedback,
            failure_signals: value.failure_signals,
            self_heal: value.self_heal,
            recall: value.recall,
            skills: value.skills,
            keystore: value.keystore,
            limits: value.limits,
            import: value.import,
            models: None,
            browser: value.browser,
            desktop: value.desktop,
            merge_queue: value.merge_queue,
            gpu: value.gpu,
            native_mail: value.native_mail,
            device_sync: value.device_sync,
            connectors: value.connectors,
            embedding: value.embedding,
            line: value.line,
            linear: value.linear,
            privacy_posture: value.privacy_posture,
            failure_signal_export: value.failure_signal_export,
            failure_signal_training: value.failure_signal_training,
            hosted_kms_key_ref: value.hosted_kms_key_ref,
            maximum_tier: value.maximum_tier,
            device_class: value.device_class,
            esign_delivery_outbox_dir: None,
            cloud_registration_pins: None,
            publisher_training_outbox_dir: None,
            publisher_training_self_host_shipper: None,
            publisher_training_intake_origin: None,
        }
    }
}

#[derive(Clone, Default)]
struct PartialServeConfig {
    vault_path: Option<PathBuf>,
    host: Option<String>,
    port: Option<u16>,
    artifact_port: Option<u16>,
    auth_secret: Option<String>,
    oauth_issuer: Option<String>,
    oauth_jwks_uri: Option<String>,
    oauth_resource_indicator: Option<String>,
    kit_bundle_public_urls: Option<Vec<String>>,
    allow_unauthenticated: Option<bool>,
    allowed_origins: Option<Vec<String>>,
    artifact_domains: Option<Vec<String>>,
    artifact_vault_name: Option<String>,
    trusted_proxies: Option<Vec<String>>,
    lease_vault_id: Option<u64>,
    dimensions: Option<usize>,
    fast_dims: Option<u16>,
    map_size: Option<usize>,
    log_level: Option<String>,
    dict_search_paths: Option<Vec<PathBuf>>,
    assistant_display_names: Option<Vec<String>>,
    default_window_count: Option<u8>,
    compaction_threshold_bytes: Option<u32>,
    compaction_throttle_secs: Option<u32>,
    bulk_chunk_size: Option<usize>,
    max_frame_size: Option<usize>,
    max_update_payload: Option<usize>,
    max_windows_per_connection: Option<usize>,
    max_messages_per_sec: Option<u32>,
    ephemeral_timeout_ms: Option<i64>,
    max_ephemeral_payload_bytes: Option<usize>,
    max_ephemeral_snapshot_bytes: Option<usize>,
    max_entity_blob: Option<usize>,
    max_lfs_object_bytes: Option<u64>,
    max_bulk_decompressed: Option<usize>,
    runtime: Option<RuntimeConfigOverride>,
    embedder: Option<EmbedderConfigOverride>,
    oneironer: Option<OneironerConfigOverride>,
    backup: Option<BackupConfigOverride>,
    feedback: Option<FeedbackConfigOverride>,
    failure_signals: Option<FailureSignalsConfigOverride>,
    self_heal: Option<SelfHealConfigOverride>,
    recall: Option<RecallConfigOverride>,
    skills: Option<SkillsConfigOverride>,
    keystore: Option<KeystoreConfigOverride>,
    limits: Option<LimitsConfigOverride>,
    import: Option<ImportConfigOverride>,
    /// `[models]` is file-only: it is too structured for env or argv.
    models: Option<ModelsConfig>,
    /// `[browser]` is file-only, as `[models]` is.
    browser: Option<super::BrowserConfig>,
    /// `[desktop]` is file-only, as `[browser]` is.
    desktop: Option<super::DesktopConfig>,
    /// `[merge_queue]` is file-only, as `[browser]` is.
    merge_queue: Option<super::MergeQueueCheckerConfig>,
    /// `[gpu]` is file-only, as `[browser]` is.
    gpu: Option<crate::runtime::GpuPoolConfig>,
    /// `[native_mail]` is file-only, as `[browser]` is.
    native_mail: Option<super::NativeMailConfig>,
    /// `[device_sync]` is file-only, as `[native_mail]` is.
    device_sync: Option<super::DeviceSyncConfig>,
    /// `[connectors.<name>]` is file-only, as `[native_mail]` is.
    connectors: Option<std::collections::BTreeMap<String, super::ConnectorHostConfig>>,
    /// `[embedding]` is file-only, as `[models]` is.
    embedding: Option<super::EmbeddingConfig>,
    /// `[line]` is file-only, as `[browser]` is.
    line: Option<super::LineConfig>,
    /// `[linear]` is file-only, as `[native_mail]` is; a plain serve's
    /// `ONEIRON_LINEAR_*` environment is read beside it at serve start.
    linear: Option<super::LinearConfig>,
    privacy_posture: Option<HostingPrivacyPosture>,
    failure_signal_export: Option<bool>,
    failure_signal_training: Option<bool>,
    hosted_kms_key_ref: Option<String>,
    /// `maximum_tier` is file-only: `oneiron init --maximum-tier` writes it.
    maximum_tier: Option<bool>,
    /// `device_class` is file-only, as `maximum_tier` is.
    device_class: Option<oneiron::authority::MachineDeviceClass>,
    /// `--esign-delivery-outbox-dir` is argv-only: no file key, no env.
    esign_delivery_outbox_dir: Option<PathBuf>,
    /// `--cloud-registration-pins` is argv-only, as the outbox: no file key,
    /// no env, no owner setting (G7).
    cloud_registration_pins: Option<PathBuf>,
    /// `--publisher-training-outbox-dir` is argv-only: no file key, no env.
    publisher_training_outbox_dir: Option<PathBuf>,
    /// `--publisher-training-self-host-shipper` is argv-only, as the outbox.
    publisher_training_self_host_shipper: Option<bool>,
    /// `--publisher-training-intake-origin` is argv-only, as the outbox.
    publisher_training_intake_origin: Option<String>,
}

impl fmt::Debug for PartialServeConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PartialServeConfig")
            .field("vault_path", &self.vault_path)
            .field("host", &self.host)
            .field("port", &self.port)
            .field("artifact_port", &self.artifact_port)
            .field("auth_secret", &redacted_secret(&self.auth_secret))
            .field("oauth_issuer", &self.oauth_issuer)
            .field("oauth_jwks_uri", &self.oauth_jwks_uri)
            .field("oauth_resource_indicator", &self.oauth_resource_indicator)
            .field("kit_bundle_public_urls", &self.kit_bundle_public_urls)
            .field("allow_unauthenticated", &self.allow_unauthenticated)
            .field("allowed_origins", &self.allowed_origins)
            .field("artifact_domains", &self.artifact_domains)
            .field("artifact_vault_name", &self.artifact_vault_name)
            .field("trusted_proxies", &self.trusted_proxies)
            .field("lease_vault_id", &self.lease_vault_id)
            .field("dimensions", &self.dimensions)
            .field("fast_dims", &self.fast_dims)
            .field("map_size", &self.map_size)
            .field("log_level", &self.log_level)
            .field("dict_search_paths", &self.dict_search_paths)
            .field("assistant_display_names", &self.assistant_display_names)
            .field("default_window_count", &self.default_window_count)
            .field(
                "compaction_threshold_bytes",
                &self.compaction_threshold_bytes,
            )
            .field("compaction_throttle_secs", &self.compaction_throttle_secs)
            .field("bulk_chunk_size", &self.bulk_chunk_size)
            .field("max_frame_size", &self.max_frame_size)
            .field("max_update_payload", &self.max_update_payload)
            .field(
                "max_windows_per_connection",
                &self.max_windows_per_connection,
            )
            .field("max_messages_per_sec", &self.max_messages_per_sec)
            .field("ephemeral_timeout_ms", &self.ephemeral_timeout_ms)
            .field(
                "max_ephemeral_payload_bytes",
                &self.max_ephemeral_payload_bytes,
            )
            .field(
                "max_ephemeral_snapshot_bytes",
                &self.max_ephemeral_snapshot_bytes,
            )
            .field("max_entity_blob", &self.max_entity_blob)
            .field("max_lfs_object_bytes", &self.max_lfs_object_bytes)
            .field("max_bulk_decompressed", &self.max_bulk_decompressed)
            .field("runtime", &self.runtime)
            .field("embedder", &self.embedder)
            .field("oneironer", &self.oneironer)
            .field("backup", &self.backup)
            .field("feedback", &self.feedback)
            .field("failure_signals", &self.failure_signals)
            .field("self_heal", &self.self_heal)
            .field("recall", &self.recall)
            .field("skills", &self.skills)
            .field("keystore", &self.keystore)
            .field("limits", &self.limits)
            .field("import", &self.import)
            .field("models", &self.models)
            .field("browser", &self.browser)
            .field("desktop", &self.desktop)
            .field("merge_queue", &self.merge_queue)
            .field("gpu", &self.gpu)
            .field("native_mail", &self.native_mail)
            .field("device_sync", &self.device_sync)
            .field("connectors", &self.connectors)
            .field("embedding", &self.embedding)
            .field("line", &self.line)
            .field("linear", &self.linear)
            .field("privacy_posture", &self.privacy_posture)
            .field(
                "hosted_kms_key_ref",
                &redacted_secret(&self.hosted_kms_key_ref),
            )
            .field("maximum_tier", &self.maximum_tier)
            .field("device_class", &self.device_class)
            .field("esign_delivery_outbox_dir", &self.esign_delivery_outbox_dir)
            .field("cloud_registration_pins", &self.cloud_registration_pins)
            .field(
                "publisher_training_outbox_dir",
                &self.publisher_training_outbox_dir,
            )
            .field(
                "publisher_training_self_host_shipper",
                &self.publisher_training_self_host_shipper,
            )
            .field(
                "publisher_training_intake_origin",
                &self.publisher_training_intake_origin,
            )
            .finish()
    }
}

impl From<&ServeArgs> for PartialServeConfig {
    fn from(value: &ServeArgs) -> Self {
        Self {
            // `--data-dir` is the managed spelling of the same directory, so
            // the unmanaged merger honours it too rather than accepting it and
            // silently ignoring it. Strictly lower precedence than
            // `--vault-path`, so an argv without `--data-dir` resolves exactly
            // as it did before the flag existed.
            vault_path: value.vault_path.clone().or_else(|| value.data_dir.clone()),
            host: value.host.clone(),
            port: value.port,
            artifact_port: value.artifact_port,
            auth_secret: value.auth_secret.clone(),
            oauth_issuer: value.oauth_issuer.clone(),
            oauth_jwks_uri: value.oauth_jwks_uri.clone(),
            oauth_resource_indicator: value.oauth_resource_indicator.clone(),
            kit_bundle_public_urls: value.kit_bundle_public_urls.clone(),
            allow_unauthenticated: value.insecure_allow_unauthenticated,
            allowed_origins: value.allowed_origins.clone(),
            artifact_domains: value.artifact_domains.clone(),
            artifact_vault_name: value.artifact_vault_name.clone(),
            trusted_proxies: value.trusted_proxies.clone(),
            lease_vault_id: value.lease_vault_id,
            dimensions: value.dimensions,
            fast_dims: value.fast_dims,
            map_size: value.map_size,
            log_level: value.log_level.clone(),
            dict_search_paths: value.dict_search_paths.clone(),
            assistant_display_names: value.assistant_display_names.clone(),
            default_window_count: value.default_window_count,
            compaction_threshold_bytes: value.compaction_threshold_bytes,
            compaction_throttle_secs: value.compaction_throttle_secs,
            bulk_chunk_size: value.bulk_chunk_size,
            max_frame_size: value.max_frame_size,
            max_update_payload: value.max_update_payload,
            max_windows_per_connection: value.max_windows_per_connection,
            max_messages_per_sec: value.max_messages_per_sec,
            ephemeral_timeout_ms: value.ephemeral_timeout_ms,
            max_ephemeral_payload_bytes: value.max_ephemeral_payload_bytes,
            max_ephemeral_snapshot_bytes: value.max_ephemeral_snapshot_bytes,
            max_entity_blob: value.max_entity_blob,
            max_lfs_object_bytes: value.max_lfs_object_bytes,
            max_bulk_decompressed: value.max_bulk_decompressed,
            runtime: runtime_override_from_args(value),
            embedder: embedder_override_from_args(value),
            oneironer: Some(OneironerConfigOverride::from(&value.oneironer))
                .filter(|over| !over.is_empty()),
            backup: None,
            feedback: None,
            failure_signals: None,
            self_heal: None,
            recall: None,
            skills: None,
            keystore: value
                .keystore_dir
                .clone()
                .map(|dir| KeystoreConfigOverride {
                    dir: Some(dir),
                    ..KeystoreConfigOverride::default()
                }),
            limits: None,
            import: None,
            models: None,
            browser: None,
            desktop: None,
            merge_queue: None,
            gpu: None,
            native_mail: None,
            device_sync: None,
            connectors: None,
            embedding: None,
            line: None,
            linear: None,
            privacy_posture: value.privacy_posture,
            failure_signal_export: value.failure_signal_export,
            failure_signal_training: value.failure_signal_training,
            hosted_kms_key_ref: value.hosted_kms_key_ref.clone(),
            maximum_tier: None,
            device_class: None,
            esign_delivery_outbox_dir: value.esign_delivery_outbox_dir.clone(),
            cloud_registration_pins: value.cloud_registration_pins.clone(),
            publisher_training_outbox_dir: value.publisher_training_outbox_dir.clone(),
            publisher_training_self_host_shipper: value
                .publisher_training_self_host_shipper
                .then_some(true),
            publisher_training_intake_origin: value.publisher_training_intake_origin.clone(),
        }
    }
}

fn embedder_override_from_args(args: &ServeArgs) -> Option<EmbedderConfigOverride> {
    let over = EmbedderConfigOverride::from(&args.embedder);
    (!over.is_empty()).then_some(over)
}
