use clap::Parser;

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
#[derive(Debug, Clone)]
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
            max_frame_size: 4 * 1024 * 1024,     // 4 MB
            max_update_payload: 2 * 1024 * 1024, // 2 MB
            max_windows_per_connection: 4096,
            max_messages_per_sec: 200,
            max_entity_blob: 64 * 1024,             // 64 KB
            max_bulk_decompressed: 8 * 1024 * 1024, // 8 MB
        }
    }
}

/// CLI arguments for the sync server binary.
#[derive(Parser, Debug)]
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

    /// Insecure local/dev escape hatch: allow requests without auth_secret.
    #[arg(long, default_value_t = false)]
    pub insecure_allow_unauthenticated: bool,

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
