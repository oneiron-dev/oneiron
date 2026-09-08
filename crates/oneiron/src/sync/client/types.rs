//! Sync client configuration, events, and sync_state key constants.

/// Client-side sync configuration.
#[derive(Debug, Clone)]
pub struct SyncClientConfig {
    /// WebSocket server URL (e.g., "wss://user-{id}.fly.dev/ws").
    pub server_url: String,
    /// Auth token (WorkOS JWT for production, shared secret for Phase 1).
    pub auth_token: String,
    /// Number of default windows to sync (current + previous). Default: 2.
    pub default_window_count: u8,
    /// Debounce interval for rapid edits before sending. Default: 50ms.
    pub sync_debounce_ms: u32,
    /// Maximum reconnection backoff delay. Default: 60s.
    pub reconnect_backoff_max_ms: u32,
    /// Initial reconnection delay. Default: 1s.
    pub reconnect_initial_ms: u32,
    /// Ephemeral state inactivity timeout in milliseconds. Default: 30s.
    pub ephemeral_timeout_ms: i64,
}

impl Default for SyncClientConfig {
    fn default() -> Self {
        Self {
            server_url: String::new(),
            auth_token: String::new(),
            default_window_count: 2,
            sync_debounce_ms: 50,
            reconnect_backoff_max_ms: 60_000,
            reconnect_initial_ms: 1_000,
            ephemeral_timeout_ms: 30_000,
        }
    }
}

/// Sync status reported by the client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncStatus {
    Disconnected,
    Connecting,
    Connected,
    Synced,
}

/// Events emitted by the sync client for the host application.
#[derive(Debug)]
pub enum SyncEvent {
    StatusChanged(SyncStatus),
    WindowUpdated {
        window_key: String,
    },
    BulkTransferComplete {
        window_key: String,
    },
    /// The server rejected this device's lease request (ONE-1140: binding
    /// conflict or revoked binding). Sync PROCEEDS — fail-closed lives at
    /// the replay doors (peers quarantine this device's NEW receipts), not
    /// the pipe.
    LeaseDenied {
        client_id: u64,
    },
    EphemeralChanged {
        origin: EphemeralChangeOrigin,
        added: Vec<String>,
        updated: Vec<String>,
        removed: Vec<String>,
    },
    Error(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EphemeralChangeOrigin {
    Local,
    Remote,
    Timeout,
}

/// Root doc snapshot row (ARCH-0023b key table: server-write-only
/// `meta.windows`; client persists what it imported).
pub(super) const KEY_ROOT_DOC: &str = "d:root";

/// Root doc state vector row (StateVector V1 encoded).
pub(super) const KEY_ROOT_SV: &str = "sv:root";

/// Root state-vector freshness flag (1 = fresh, 0 = stale).
pub(super) const KEY_ROOT_SVF: &str = "svf:root";

/// Pending root update rows applied on top of `d:root` at startup (step 1).
pub(super) const ROOT_UPDATE_PREFIX: &str = "u:root:";

/// This device's CRDT client id (u64 LE, 8 bytes) — minted once, stable per
/// install. The mint lives in `crate::identity` (ONE-1140, OD-2); this
/// test-side literal pins the row key independently of that module.
#[cfg(test)]
pub(super) const KEY_CLIENT_ID: &str = "m:client_id";

/// Last successful sync timestamp (u64 LE, 8 bytes).
pub(super) const KEY_LAST_SYNC: &str = "m:last_sync";

/// `svf:*` byte meaning "the persisted `sv:*` reflects the full doc state".
pub(super) const SVF_FRESH: u8 = 1;
