use clap::Parser;

/// Oneiron sync server configuration.
#[derive(Debug, Clone)]
#[allow(dead_code)] // Config fields consumed by WebSocket handler in Phase 1D
pub struct SyncServerConfig {
    /// Number of default windows to load (current + previous months).
    pub default_window_count: u8,
    /// Byte threshold that triggers CRDT Doc compaction.
    pub compaction_threshold_bytes: u32,
    /// Minimum seconds between compaction runs.
    pub compaction_throttle_secs: u32,
    /// Maximum uncompressed BulkTransfer chunk size in bytes.
    pub bulk_chunk_size: usize,
    /// Shared secret for Phase 1 API auth (header-based).
    pub auth_secret: Option<String>,
    /// Maximum WebSocket frame size in bytes.
    pub max_frame_size: usize,
    /// Maximum CRDT update payload in bytes.
    pub max_update_payload: usize,
    /// Maximum entity blob size in bytes.
    pub max_entity_blob: usize,
    /// Maximum decompressed BulkTransfer chunk in bytes.
    pub max_bulk_decompressed: usize,
    /// Maximum updates per second per client.
    pub max_updates_per_sec: u32,
    /// Maximum concurrent connections per user.
    pub max_connections_per_user: u32,
    /// Maximum loaded windows per client connection.
    pub max_windows_per_client: u8,
}

impl Default for SyncServerConfig {
    fn default() -> Self {
        Self {
            default_window_count: 2,
            compaction_threshold_bytes: 524_288, // 512 KB
            compaction_throttle_secs: 30,
            bulk_chunk_size: 1_048_576, // 1 MB uncompressed
            auth_secret: None,
            max_frame_size: 4 * 1024 * 1024,         // 4 MB
            max_update_payload: 2 * 1024 * 1024,      // 2 MB
            max_entity_blob: 64 * 1024,               // 64 KB
            max_bulk_decompressed: 8 * 1024 * 1024,   // 8 MB
            max_updates_per_sec: 100,
            max_connections_per_user: 5,
            max_windows_per_client: 4,
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
