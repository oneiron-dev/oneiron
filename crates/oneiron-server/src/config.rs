use std::collections::HashMap;
use std::fmt;
use std::path::{Path, PathBuf};

use anyhow::Context;
use clap::Args;
use serde::Deserialize;

const DEFAULT_CONFIG_FILE: &str = "oneiron.toml";
const DEFAULT_CONFIG_DIR: &str = "oneiron";
const LEGACY_DEFAULT_VAULT_PATH: &str = "./vault";

/// Oneiron sync server configuration.
///
/// Server-side enforcement status of the per-client limits (ONE-1129
/// OWNER-DECISION, recorded in the PR body):
/// - `max_update_payload` — ENFORCED at the WindowSync UPDATE chokepoint
///   (oversized updates close the connection before any state mutates).
/// - `max_frame_size` — ENFORCED on the WebSocket frame size.
/// - `max_messages_per_sec` — ENFORCED as a per-connection inbound message
///   rate limit. Per-user limits still need per-user identity (Phase-1 auth is
///   a single shared secret).
/// - `max_windows_per_connection` — ENFORCED as a generous per-connection
///   distinct-window touch cap. The default is intentionally high enough for
///   legitimate historical-window tombstone sync; it stops fabricated-key
///   floods, not real history.
/// - `max_connections_per_user` — not enforced until auth has per-user
///   identity.
#[derive(Clone)]
pub struct SyncServerConfig {
    /// Number of default windows to load (current + previous months).
    /// Read when M5 default-window preloading lands.
    pub default_window_count: u8,
    /// Byte threshold that triggers CRDT Doc compaction (M5).
    pub compaction_threshold_bytes: u32,
    /// Minimum seconds between compaction runs (M5).
    pub compaction_throttle_secs: u32,
    /// Maximum uncompressed BulkTransfer chunk size in bytes (M5 Phase-3
    /// bulk sender).
    pub bulk_chunk_size: usize,
    /// Shared secret for Phase 1 auth (`x-oneiron-secret` header) — checked
    /// on both the HTTP API and the `/ws` upgrade.
    pub auth_secret: Option<String>,
    /// Explicit local/dev escape hatch for running without `auth_secret`.
    pub allow_unauthenticated: bool,
    /// Explicit CORS origins allowed to call the HTTP API. Empty is
    /// fail-closed: no cross-origin browser access is granted.
    pub allowed_origins: Vec<String>,
    /// Maximum WebSocket frame size in bytes.
    pub max_frame_size: usize,
    /// Maximum CRDT update payload in bytes (enforced on WindowSync UPDATE).
    pub max_update_payload: usize,
    /// Maximum distinct valid windows one connection may touch.
    pub max_windows_per_connection: usize,
    /// Maximum inbound protocol messages per connection per second.
    pub max_messages_per_sec: u32,
    /// Maximum entity blob size in bytes (M5/M6 bulk + materialization paths).
    pub max_entity_blob: usize,
    /// Maximum decompressed BulkTransfer chunk in bytes (M5 Phase-3).
    pub max_bulk_decompressed: usize,
}

impl Default for SyncServerConfig {
    fn default() -> Self {
        Self {
            default_window_count: 2,
            compaction_threshold_bytes: 524_288, // 512 KB
            compaction_throttle_secs: 30,
            bulk_chunk_size: 1_048_576, // 1 MB uncompressed
            auth_secret: None,
            allow_unauthenticated: false,
            allowed_origins: Vec::new(),
            max_frame_size: 4 * 1024 * 1024,     // 4 MB
            max_update_payload: 2 * 1024 * 1024, // 2 MB
            max_windows_per_connection: 4096,
            max_messages_per_sec: 200,
            max_entity_blob: 64 * 1024,             // 64 KB
            max_bulk_decompressed: 8 * 1024 * 1024, // 8 MB
        }
    }
}

impl fmt::Debug for SyncServerConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SyncServerConfig")
            .field("default_window_count", &self.default_window_count)
            .field(
                "compaction_threshold_bytes",
                &self.compaction_threshold_bytes,
            )
            .field("compaction_throttle_secs", &self.compaction_throttle_secs)
            .field("bulk_chunk_size", &self.bulk_chunk_size)
            .field("auth_secret", &redacted_secret(&self.auth_secret))
            .field("allow_unauthenticated", &self.allow_unauthenticated)
            .field("allowed_origins", &self.allowed_origins)
            .field("max_frame_size", &self.max_frame_size)
            .field("max_update_payload", &self.max_update_payload)
            .field(
                "max_windows_per_connection",
                &self.max_windows_per_connection,
            )
            .field("max_messages_per_sec", &self.max_messages_per_sec)
            .field("max_entity_blob", &self.max_entity_blob)
            .field("max_bulk_decompressed", &self.max_bulk_decompressed)
            .finish()
    }
}

/// Serve command flags. All fields are optional so the config merger can keep
/// the required precedence: file, then environment, then CLI flags.
#[derive(Args, Clone, Default)]
pub struct ServeArgs {
    /// Path to a TOML config file. Defaults to the XDG oneiron config path
    /// when present.
    #[arg(long)]
    pub config: Option<PathBuf>,

    /// Path to the LMDB vault directory.
    #[arg(long)]
    pub vault_path: Option<PathBuf>,

    /// Host address to bind to.
    #[arg(long)]
    pub host: Option<String>,

    /// Port to bind to.
    #[arg(long)]
    pub port: Option<u16>,

    /// Shared secret for API authentication (Phase 1).
    #[arg(long)]
    pub auth_secret: Option<String>,

    /// Insecure local/dev escape hatch: allow requests without auth_secret.
    #[arg(
        long = "insecure-allow-unauthenticated",
        num_args = 0..=1,
        default_missing_value = "true",
        value_parser = clap::value_parser!(bool)
    )]
    pub insecure_allow_unauthenticated: Option<bool>,

    /// Comma-separated CORS origins allowed to call the HTTP API.
    #[arg(
        long = "allowed-origins",
        visible_alias = "cors-origins",
        value_delimiter = ',',
        num_args = 1..
    )]
    pub allowed_origins: Option<Vec<String>>,

    /// Embedding vector dimension for the vault.
    #[arg(long)]
    pub dimensions: Option<usize>,

    /// LMDB map size in bytes.
    #[arg(long)]
    pub map_size: Option<usize>,

    /// Log level filter (e.g., "info", "debug", "oneiron_server=debug").
    #[arg(long)]
    pub log_level: Option<String>,

    /// Comma-separated trusted roots containing ja/ko/zh dictionary assets.
    #[arg(long = "dict-search-paths", value_delimiter = ',', num_args = 1..)]
    pub dict_search_paths: Option<Vec<PathBuf>>,

    /// Number of default windows to preload.
    #[arg(long)]
    pub default_window_count: Option<u8>,

    /// Byte threshold that triggers CRDT Doc compaction.
    #[arg(long)]
    pub compaction_threshold_bytes: Option<u32>,

    /// Minimum seconds between compaction runs.
    #[arg(long)]
    pub compaction_throttle_secs: Option<u32>,

    /// Maximum uncompressed BulkTransfer chunk size in bytes.
    #[arg(long)]
    pub bulk_chunk_size: Option<usize>,

    /// Maximum WebSocket frame size in bytes.
    #[arg(long)]
    pub max_frame_size: Option<usize>,

    /// Maximum CRDT update payload in bytes.
    #[arg(long)]
    pub max_update_payload: Option<usize>,

    /// Maximum distinct valid windows one connection may touch.
    #[arg(long)]
    pub max_windows_per_connection: Option<usize>,

    /// Maximum inbound protocol messages per connection per second.
    #[arg(long)]
    pub max_messages_per_sec: Option<u32>,

    /// Maximum entity blob size in bytes.
    #[arg(long)]
    pub max_entity_blob: Option<usize>,

    /// Maximum decompressed BulkTransfer chunk in bytes.
    #[arg(long)]
    pub max_bulk_decompressed: Option<usize>,
}

impl fmt::Debug for ServeArgs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServeArgs")
            .field("config", &self.config)
            .field("vault_path", &self.vault_path)
            .field("host", &self.host)
            .field("port", &self.port)
            .field("auth_secret", &redacted_secret(&self.auth_secret))
            .field(
                "insecure_allow_unauthenticated",
                &self.insecure_allow_unauthenticated,
            )
            .field("allowed_origins", &self.allowed_origins)
            .field("dimensions", &self.dimensions)
            .field("map_size", &self.map_size)
            .field("log_level", &self.log_level)
            .field("dict_search_paths", &self.dict_search_paths)
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
            .field("max_entity_blob", &self.max_entity_blob)
            .field("max_bulk_decompressed", &self.max_bulk_decompressed)
            .finish()
    }
}

/// Fully resolved serve configuration after defaults, config file, env vars,
/// and flags have been merged.
#[derive(Clone, PartialEq, Eq)]
pub struct ServeConfig {
    pub vault_path: PathBuf,
    pub host: String,
    pub port: u16,
    pub auth_secret: Option<String>,
    pub allow_unauthenticated: bool,
    pub allowed_origins: Vec<String>,
    pub dimensions: usize,
    pub map_size: usize,
    pub log_level: String,
    pub dict_search_paths: Vec<PathBuf>,
    pub default_window_count: u8,
    pub compaction_threshold_bytes: u32,
    pub compaction_throttle_secs: u32,
    pub bulk_chunk_size: usize,
    pub max_frame_size: usize,
    pub max_update_payload: usize,
    pub max_windows_per_connection: usize,
    pub max_messages_per_sec: u32,
    pub max_entity_blob: usize,
    pub max_bulk_decompressed: usize,
}

impl Default for ServeConfig {
    fn default() -> Self {
        let server = SyncServerConfig::default();
        let vault = oneiron::VaultConfig::server();

        Self {
            vault_path: PathBuf::from(LEGACY_DEFAULT_VAULT_PATH),
            host: "0.0.0.0".to_owned(),
            port: 9090,
            auth_secret: server.auth_secret,
            allow_unauthenticated: server.allow_unauthenticated,
            allowed_origins: server.allowed_origins,
            dimensions: vault.dimensions,
            map_size: vault.map_size,
            log_level: "info".to_owned(),
            dict_search_paths: vault.dict_search_paths,
            default_window_count: server.default_window_count,
            compaction_threshold_bytes: server.compaction_threshold_bytes,
            compaction_throttle_secs: server.compaction_throttle_secs,
            bulk_chunk_size: server.bulk_chunk_size,
            max_frame_size: server.max_frame_size,
            max_update_payload: server.max_update_payload,
            max_windows_per_connection: server.max_windows_per_connection,
            max_messages_per_sec: server.max_messages_per_sec,
            max_entity_blob: server.max_entity_blob,
            max_bulk_decompressed: server.max_bulk_decompressed,
        }
    }
}

impl fmt::Debug for ServeConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServeConfig")
            .field("vault_path", &self.vault_path)
            .field("host", &self.host)
            .field("port", &self.port)
            .field("auth_secret", &redacted_secret(&self.auth_secret))
            .field("allow_unauthenticated", &self.allow_unauthenticated)
            .field("allowed_origins", &self.allowed_origins)
            .field("dimensions", &self.dimensions)
            .field("map_size", &self.map_size)
            .field("log_level", &self.log_level)
            .field("dict_search_paths", &self.dict_search_paths)
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
            .field("max_entity_blob", &self.max_entity_blob)
            .field("max_bulk_decompressed", &self.max_bulk_decompressed)
            .finish()
    }
}

impl ServeConfig {
    pub fn sync_server_config(&self) -> SyncServerConfig {
        SyncServerConfig {
            default_window_count: self.default_window_count,
            compaction_threshold_bytes: self.compaction_threshold_bytes,
            compaction_throttle_secs: self.compaction_throttle_secs,
            bulk_chunk_size: self.bulk_chunk_size,
            auth_secret: self.auth_secret.clone(),
            allow_unauthenticated: self.allow_unauthenticated,
            allowed_origins: self.allowed_origins.clone(),
            max_frame_size: self.max_frame_size,
            max_update_payload: self.max_update_payload,
            max_windows_per_connection: self.max_windows_per_connection,
            max_messages_per_sec: self.max_messages_per_sec,
            max_entity_blob: self.max_entity_blob,
            max_bulk_decompressed: self.max_bulk_decompressed,
        }
    }

    pub fn vault_config(&self) -> oneiron::VaultConfig {
        let mut config = oneiron::VaultConfig::server();
        config.dimensions = self.dimensions;
        config.map_size = self.map_size;
        config.dict_search_paths = self.dict_search_paths.clone();
        config
    }
}

/// Environment-derived serve settings.
#[derive(Clone, Debug, Default)]
pub struct EnvConfig {
    pub config_path: Option<PathBuf>,
    values: PartialServeConfig,
}

impl EnvConfig {
    pub fn from_process() -> anyhow::Result<Self> {
        Self::from_lookup(|key| std::env::var(key).ok())
    }

    pub fn from_pairs<I, K, V>(pairs: I) -> anyhow::Result<Self>
    where
        I: IntoIterator<Item = (K, V)>,
        K: AsRef<str>,
        V: AsRef<str>,
    {
        let values: HashMap<String, String> = pairs
            .into_iter()
            .map(|(key, value)| (key.as_ref().to_owned(), value.as_ref().to_owned()))
            .collect();
        Self::from_lookup(|key| values.get(key).cloned())
    }

    fn from_lookup(mut lookup: impl FnMut(&str) -> Option<String>) -> anyhow::Result<Self> {
        let mut values = PartialServeConfig::default();
        let config_path = lookup("ONEIRON_CONFIG").map(PathBuf::from);

        values.vault_path = lookup_path(&mut lookup, "ONEIRON_VAULT_PATH");
        values.host = lookup("ONEIRON_HOST");
        values.port = lookup_parse(&mut lookup, "ONEIRON_PORT")?;
        values.auth_secret = lookup("ONEIRON_AUTH_SECRET");
        values.allow_unauthenticated =
            lookup_bool(&mut lookup, "ONEIRON_INSECURE_ALLOW_UNAUTHENTICATED")?;
        values.allowed_origins = lookup_list(&mut lookup, "ONEIRON_ALLOWED_ORIGINS");
        values.dimensions = lookup_parse(&mut lookup, "ONEIRON_DIMENSIONS")?;
        values.map_size = lookup_parse(&mut lookup, "ONEIRON_MAP_SIZE")?;
        values.log_level = lookup("ONEIRON_LOG_LEVEL");
        values.dict_search_paths = lookup_path_list(&mut lookup, "ONEIRON_DICT_SEARCH_PATHS");
        values.default_window_count = lookup_parse(&mut lookup, "ONEIRON_DEFAULT_WINDOW_COUNT")?;
        values.compaction_threshold_bytes =
            lookup_parse(&mut lookup, "ONEIRON_COMPACTION_THRESHOLD_BYTES")?;
        values.compaction_throttle_secs =
            lookup_parse(&mut lookup, "ONEIRON_COMPACTION_THROTTLE_SECS")?;
        values.bulk_chunk_size = lookup_parse(&mut lookup, "ONEIRON_BULK_CHUNK_SIZE")?;
        values.max_frame_size = lookup_parse(&mut lookup, "ONEIRON_MAX_FRAME_SIZE")?;
        values.max_update_payload = lookup_parse(&mut lookup, "ONEIRON_MAX_UPDATE_PAYLOAD")?;
        values.max_windows_per_connection =
            lookup_parse(&mut lookup, "ONEIRON_MAX_WINDOWS_PER_CONNECTION")?;
        values.max_messages_per_sec = lookup_parse(&mut lookup, "ONEIRON_MAX_MESSAGES_PER_SEC")?;
        values.max_entity_blob = lookup_parse(&mut lookup, "ONEIRON_MAX_ENTITY_BLOB")?;
        values.max_bulk_decompressed = lookup_parse(&mut lookup, "ONEIRON_MAX_BULK_DECOMPRESSED")?;

        Ok(Self {
            config_path,
            values,
        })
    }
}

pub fn resolve_serve_config(args: &ServeArgs) -> anyhow::Result<ServeConfig> {
    resolve_serve_config_with_sources(args, EnvConfig::from_process()?, default_config_path())
}

pub fn resolve_serve_config_with_sources(
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

    let mut resolved = ServeConfig::default();
    file_values.apply_to(&mut resolved);
    env.values.apply_to(&mut resolved);
    flag_values.apply_to(&mut resolved);
    Ok(resolved)
}

pub fn default_config_path() -> Option<PathBuf> {
    if let Some(base) = std::env::var_os("XDG_CONFIG_HOME") {
        return Some(
            PathBuf::from(base)
                .join(DEFAULT_CONFIG_DIR)
                .join(DEFAULT_CONFIG_FILE),
        );
    }

    std::env::var_os("HOME").map(|home| {
        PathBuf::from(home)
            .join(".config")
            .join(DEFAULT_CONFIG_DIR)
            .join(DEFAULT_CONFIG_FILE)
    })
}

fn load_file_config(path: &Path) -> anyhow::Result<PartialServeConfig> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("read config file {}", path.display()))?;
    let config: FileServeConfig =
        toml::from_str(&raw).with_context(|| format!("parse config file {}", path.display()))?;
    Ok(config.into())
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct FileServeConfig {
    vault_path: Option<PathBuf>,
    host: Option<String>,
    port: Option<u16>,
    auth_secret: Option<String>,
    allow_unauthenticated: Option<bool>,
    allowed_origins: Option<Vec<String>>,
    dimensions: Option<usize>,
    map_size: Option<usize>,
    log_level: Option<String>,
    dict_search_paths: Option<Vec<PathBuf>>,
    default_window_count: Option<u8>,
    compaction_threshold_bytes: Option<u32>,
    compaction_throttle_secs: Option<u32>,
    bulk_chunk_size: Option<usize>,
    max_frame_size: Option<usize>,
    max_update_payload: Option<usize>,
    max_windows_per_connection: Option<usize>,
    max_messages_per_sec: Option<u32>,
    max_entity_blob: Option<usize>,
    max_bulk_decompressed: Option<usize>,
}

impl From<FileServeConfig> for PartialServeConfig {
    fn from(value: FileServeConfig) -> Self {
        Self {
            vault_path: value.vault_path,
            host: value.host,
            port: value.port,
            auth_secret: value.auth_secret,
            allow_unauthenticated: value.allow_unauthenticated,
            allowed_origins: value.allowed_origins,
            dimensions: value.dimensions,
            map_size: value.map_size,
            log_level: value.log_level,
            dict_search_paths: value.dict_search_paths,
            default_window_count: value.default_window_count,
            compaction_threshold_bytes: value.compaction_threshold_bytes,
            compaction_throttle_secs: value.compaction_throttle_secs,
            bulk_chunk_size: value.bulk_chunk_size,
            max_frame_size: value.max_frame_size,
            max_update_payload: value.max_update_payload,
            max_windows_per_connection: value.max_windows_per_connection,
            max_messages_per_sec: value.max_messages_per_sec,
            max_entity_blob: value.max_entity_blob,
            max_bulk_decompressed: value.max_bulk_decompressed,
        }
    }
}

#[derive(Clone, Debug, Default)]
struct PartialServeConfig {
    vault_path: Option<PathBuf>,
    host: Option<String>,
    port: Option<u16>,
    auth_secret: Option<String>,
    allow_unauthenticated: Option<bool>,
    allowed_origins: Option<Vec<String>>,
    dimensions: Option<usize>,
    map_size: Option<usize>,
    log_level: Option<String>,
    dict_search_paths: Option<Vec<PathBuf>>,
    default_window_count: Option<u8>,
    compaction_threshold_bytes: Option<u32>,
    compaction_throttle_secs: Option<u32>,
    bulk_chunk_size: Option<usize>,
    max_frame_size: Option<usize>,
    max_update_payload: Option<usize>,
    max_windows_per_connection: Option<usize>,
    max_messages_per_sec: Option<u32>,
    max_entity_blob: Option<usize>,
    max_bulk_decompressed: Option<usize>,
}

impl PartialServeConfig {
    fn apply_to(self, resolved: &mut ServeConfig) {
        if let Some(value) = self.vault_path {
            resolved.vault_path = expand_home(value);
        }
        if let Some(value) = self.host {
            resolved.host = value;
        }
        if let Some(value) = self.port {
            resolved.port = value;
        }
        if let Some(value) = self.auth_secret {
            resolved.auth_secret = Some(value);
        }
        if let Some(value) = self.allow_unauthenticated {
            resolved.allow_unauthenticated = value;
        }
        if let Some(value) = self.allowed_origins {
            resolved.allowed_origins = normalize_list(value);
        }
        if let Some(value) = self.dimensions {
            resolved.dimensions = value;
        }
        if let Some(value) = self.map_size {
            resolved.map_size = value;
        }
        if let Some(value) = self.log_level {
            resolved.log_level = value;
        }
        if let Some(value) = self.dict_search_paths {
            resolved.dict_search_paths = value.into_iter().map(expand_home).collect();
        }
        if let Some(value) = self.default_window_count {
            resolved.default_window_count = value;
        }
        if let Some(value) = self.compaction_threshold_bytes {
            resolved.compaction_threshold_bytes = value;
        }
        if let Some(value) = self.compaction_throttle_secs {
            resolved.compaction_throttle_secs = value;
        }
        if let Some(value) = self.bulk_chunk_size {
            resolved.bulk_chunk_size = value;
        }
        if let Some(value) = self.max_frame_size {
            resolved.max_frame_size = value;
        }
        if let Some(value) = self.max_update_payload {
            resolved.max_update_payload = value;
        }
        if let Some(value) = self.max_windows_per_connection {
            resolved.max_windows_per_connection = value;
        }
        if let Some(value) = self.max_messages_per_sec {
            resolved.max_messages_per_sec = value;
        }
        if let Some(value) = self.max_entity_blob {
            resolved.max_entity_blob = value;
        }
        if let Some(value) = self.max_bulk_decompressed {
            resolved.max_bulk_decompressed = value;
        }
    }
}

impl From<&ServeArgs> for PartialServeConfig {
    fn from(value: &ServeArgs) -> Self {
        Self {
            vault_path: value.vault_path.clone(),
            host: value.host.clone(),
            port: value.port,
            auth_secret: value.auth_secret.clone(),
            allow_unauthenticated: value.insecure_allow_unauthenticated,
            allowed_origins: value.allowed_origins.clone(),
            dimensions: value.dimensions,
            map_size: value.map_size,
            log_level: value.log_level.clone(),
            dict_search_paths: value.dict_search_paths.clone(),
            default_window_count: value.default_window_count,
            compaction_threshold_bytes: value.compaction_threshold_bytes,
            compaction_throttle_secs: value.compaction_throttle_secs,
            bulk_chunk_size: value.bulk_chunk_size,
            max_frame_size: value.max_frame_size,
            max_update_payload: value.max_update_payload,
            max_windows_per_connection: value.max_windows_per_connection,
            max_messages_per_sec: value.max_messages_per_sec,
            max_entity_blob: value.max_entity_blob,
            max_bulk_decompressed: value.max_bulk_decompressed,
        }
    }
}

fn lookup_parse<T>(
    lookup: &mut impl FnMut(&str) -> Option<String>,
    key: &'static str,
) -> anyhow::Result<Option<T>>
where
    T: std::str::FromStr,
    T::Err: std::fmt::Display,
{
    lookup(key)
        .map(|value| {
            value
                .parse::<T>()
                .map_err(|e| anyhow::anyhow!("parse {key}={value:?}: {e}"))
        })
        .transpose()
}

fn lookup_bool(
    lookup: &mut impl FnMut(&str) -> Option<String>,
    key: &'static str,
) -> anyhow::Result<Option<bool>> {
    lookup(key).map(|value| parse_bool(key, &value)).transpose()
}

fn lookup_path(
    lookup: &mut impl FnMut(&str) -> Option<String>,
    key: &'static str,
) -> Option<PathBuf> {
    lookup(key).map(PathBuf::from)
}

fn lookup_list(
    lookup: &mut impl FnMut(&str) -> Option<String>,
    key: &'static str,
) -> Option<Vec<String>> {
    lookup(key).map(|value| split_list(&value))
}

fn lookup_path_list(
    lookup: &mut impl FnMut(&str) -> Option<String>,
    key: &'static str,
) -> Option<Vec<PathBuf>> {
    lookup(key).map(|value| split_list(&value).into_iter().map(PathBuf::from).collect())
}

fn parse_bool(key: &'static str, value: &str) -> anyhow::Result<bool> {
    match value.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        _ => anyhow::bail!("parse {key}={value:?}: expected true/false, yes/no, on/off, or 1/0"),
    }
}

fn split_list(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

fn normalize_list(values: Vec<String>) -> Vec<String> {
    values
        .into_iter()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
        .collect()
}

fn expand_home(path: PathBuf) -> PathBuf {
    let Some(raw) = path.to_str() else {
        return path;
    };
    if raw == "~" {
        return std::env::var_os("HOME").map(PathBuf::from).unwrap_or(path);
    }
    if let Some(suffix) = raw.strip_prefix("~/")
        && let Some(home) = std::env::var_os("HOME")
    {
        return PathBuf::from(home).join(suffix);
    }
    path
}

fn redacted_secret(secret: &Option<String>) -> Option<&'static str> {
    secret.as_ref().map(|_| "<redacted>")
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[derive(Parser)]
    struct TestCli {
        #[command(flatten)]
        serve: ServeArgs,
    }

    #[test]
    fn sync_server_config_debug_redacts_auth_secret() {
        let config = SyncServerConfig {
            auth_secret: Some("super-secret-value".to_owned()),
            ..Default::default()
        };

        let debug = format!("{config:?}");

        assert!(!debug.contains("super-secret-value"));
        assert!(debug.contains("auth_secret"));
        assert!(debug.contains("<redacted>"));
    }

    #[test]
    fn sync_server_config_debug_prints_none_for_missing_auth_secret() {
        let debug = format!("{:?}", SyncServerConfig::default());

        assert!(debug.contains("auth_secret: None"));
    }

    #[test]
    fn serve_args_debug_redacts_auth_secret() {
        let args = ServeArgs {
            auth_secret: Some("cli-secret-value".to_owned()),
            ..Default::default()
        };

        let debug = format!("{args:?}");

        assert!(!debug.contains("cli-secret-value"));
        assert!(debug.contains("auth_secret"));
        assert!(debug.contains("<redacted>"));
    }

    #[test]
    fn serve_args_debug_prints_none_for_missing_auth_secret() {
        let debug = format!("{:?}", ServeArgs::default());

        assert!(debug.contains("auth_secret: None"));
    }

    #[test]
    fn serve_config_debug_redacts_auth_secret() {
        let config = ServeConfig {
            auth_secret: Some("serve-config-secret".to_owned()),
            ..Default::default()
        };

        let debug = format!("{config:?}");

        assert!(!debug.contains("serve-config-secret"));
        assert!(debug.contains("auth_secret"));
        assert!(debug.contains("<redacted>"));
    }

    #[test]
    fn serve_config_debug_prints_none_for_missing_auth_secret() {
        let debug = format!("{:?}", ServeConfig::default());

        assert!(debug.contains("auth_secret: None"));
    }

    #[test]
    fn legacy_top_level_flags_parse_as_serve_args() {
        let cli = TestCli::try_parse_from([
            "oneiron-server",
            "--vault-path",
            "/tmp/oneiron-vault",
            "--port",
            "9191",
            "--insecure-allow-unauthenticated",
        ])
        .unwrap();

        assert_eq!(
            cli.serve.vault_path,
            Some(PathBuf::from("/tmp/oneiron-vault"))
        );
        assert_eq!(cli.serve.port, Some(9191));
        assert_eq!(cli.serve.insecure_allow_unauthenticated, Some(true));
    }

    #[test]
    fn cors_origins_alias_parses_as_serve_args() {
        let cli = TestCli::try_parse_from([
            "oneiron-server",
            "--cors-origins",
            "https://a.example,https://b.example",
        ])
        .unwrap();

        assert_eq!(
            cli.serve.allowed_origins,
            Some(vec![
                "https://a.example".to_owned(),
                "https://b.example".to_owned()
            ])
        );
    }

    #[test]
    fn env_allowed_origins_are_split_and_trimmed() {
        let env = EnvConfig::from_pairs([(
            "ONEIRON_ALLOWED_ORIGINS",
            "https://a.example, https://b.example",
        )])
        .unwrap();
        let resolved = resolve_serve_config_with_sources(&ServeArgs::default(), env, None).unwrap();

        assert_eq!(
            resolved.allowed_origins,
            vec!["https://a.example", "https://b.example"]
        );
    }

    #[test]
    fn config_file_env_and_flags_merge_in_precedence_order() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("oneiron.toml");
        std::fs::write(
            &config_path,
            r#"
vault_path = "/file/vault"
host = "file-host"
port = 1000
allowed_origins = ["https://file.example"]
dimensions = 128
map_size = 67108864
log_level = "warn"
max_frame_size = 11
"#,
        )
        .unwrap();
        let env = EnvConfig::from_pairs([
            ("ONEIRON_CONFIG", config_path.to_str().unwrap()),
            ("ONEIRON_HOST", "env-host"),
            ("ONEIRON_PORT", "2000"),
            ("ONEIRON_AUTH_SECRET", "env-secret"),
        ])
        .unwrap();
        let flags = ServeArgs {
            host: Some("flag-host".to_owned()),
            allowed_origins: Some(vec!["https://flag.example".to_owned()]),
            ..Default::default()
        };

        let resolved = resolve_serve_config_with_sources(&flags, env, None).unwrap();

        assert_eq!(resolved.vault_path, PathBuf::from("/file/vault"));
        assert_eq!(resolved.host, "flag-host");
        assert_eq!(resolved.port, 2000);
        assert_eq!(resolved.auth_secret.as_deref(), Some("env-secret"));
        assert_eq!(resolved.allowed_origins, vec!["https://flag.example"]);
        assert_eq!(resolved.dimensions, 128);
        assert_eq!(resolved.map_size, 67_108_864);
        assert_eq!(resolved.log_level, "warn");
        assert_eq!(resolved.max_frame_size, 11);
    }
}
