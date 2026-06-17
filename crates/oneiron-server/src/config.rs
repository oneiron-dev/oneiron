use std::fmt;

use clap::Parser;

/// Oneiron sync server configuration.
///
/// Server-side enforcement status of the per-client limits (ONE-1129
/// OWNER-DECISION, recorded in the PR body):
/// - `max_update_payload` — ENFORCED at the WindowSync UPDATE chokepoint
///   (oversized updates close the connection before any state mutates).
/// - `max_frame_size` — ENFORCED on the WebSocket frame size.
/// - `max_updates_per_sec`, `max_connections_per_user`,
///   `max_windows_per_client` — DELETED, deferred to M6 (rate-limit tuning).
///   Per-user limits need per-user identity (Phase-1 auth is a single shared
///   secret), and a hard per-connection window cap can block legitimate
///   tombstone sync into historical windows — weakening delete propagation
///   is not acceptable to enforce a quota.
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
    /// Explicit CORS origins allowed to call the HTTP API. Empty is
    /// fail-closed: no cross-origin browser access is granted.
    pub allowed_origins: Vec<String>,
    /// Maximum WebSocket frame size in bytes.
    pub max_frame_size: usize,
    /// Maximum CRDT update payload in bytes (enforced on WindowSync UPDATE).
    pub max_update_payload: usize,
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
            allowed_origins: Vec::new(),
            max_frame_size: 4 * 1024 * 1024,        // 4 MB
            max_update_payload: 2 * 1024 * 1024,    // 2 MB
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
            .field("allowed_origins", &self.allowed_origins)
            .field("max_frame_size", &self.max_frame_size)
            .field("max_update_payload", &self.max_update_payload)
            .field("max_entity_blob", &self.max_entity_blob)
            .field("max_bulk_decompressed", &self.max_bulk_decompressed)
            .finish()
    }
}

/// CLI arguments for the sync server binary.
#[derive(Parser)]
#[command(name = "oneiron-server", about = "Oneiron CRDT sync server")]
pub struct CliArgs {
    /// Path to the LMDB vault directory.
    #[arg(long, default_value = "./vault")]
    pub vault_path: String,

    /// Host address to bind to.
    #[arg(long, default_value = "0.0.0.0")]
    pub host: String,

    /// Port to bind to.
    #[arg(long, default_value_t = 9090)]
    pub port: u16,

    /// Shared secret for API authentication (Phase 1).
    #[arg(long, env = "ONEIRON_AUTH_SECRET")]
    pub auth_secret: Option<String>,

    /// Comma-separated CORS origins allowed to call the HTTP API.
    #[arg(
        long = "allowed-origins",
        env = "ONEIRON_ALLOWED_ORIGINS",
        value_delimiter = ','
    )]
    pub allowed_origins: Vec<String>,

    /// Embedding vector dimension for the vault.
    #[arg(long, default_value_t = 4096)]
    pub dimensions: usize,

    /// LMDB map size in bytes.
    #[arg(long, default_value_t = 1 << 33)]
    pub map_size: usize,

    /// Log level filter (e.g., "info", "debug", "oneiron_server=debug").
    #[arg(long, default_value = "info")]
    pub log_level: String,
}

impl fmt::Debug for CliArgs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CliArgs")
            .field("vault_path", &self.vault_path)
            .field("host", &self.host)
            .field("port", &self.port)
            .field("auth_secret", &redacted_secret(&self.auth_secret))
            .field("allowed_origins", &self.allowed_origins)
            .field("dimensions", &self.dimensions)
            .field("map_size", &self.map_size)
            .field("log_level", &self.log_level)
            .finish()
    }
}

fn redacted_secret(secret: &Option<String>) -> Option<&'static str> {
    secret.as_ref().map(|_| "<redacted>")
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn cli_args_debug_redacts_auth_secret() {
        let args = CliArgs {
            vault_path: "./vault".to_owned(),
            host: "127.0.0.1".to_owned(),
            port: 9090,
            auth_secret: Some("cli-secret-value".to_owned()),
            allowed_origins: vec!["https://app.example".to_owned()],
            dimensions: 4096,
            map_size: 1 << 33,
            log_level: "info".to_owned(),
        };

        let debug = format!("{args:?}");

        assert!(!debug.contains("cli-secret-value"));
        assert!(debug.contains("auth_secret"));
        assert!(debug.contains("<redacted>"));
    }
}
