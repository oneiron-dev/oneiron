//! Sync client configuration, events, and sync_state key constants.

/// How an own device keeps ledger windows resident.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SyncResidenceMode {
    /// Root and index at enrol; items are fetched on demand.
    #[default]
    Opened,
    /// Explicit opt-in to full month-window replication.
    All,
}

/// Client-side sync configuration.
#[derive(Debug, Clone)]
pub struct SyncClientConfig {
    /// Non-home devices default to opened items; full replication is opt-in.
    pub residence_mode: SyncResidenceMode,
    /// Grant selector supplied by the authenticated host for index, first touch,
    /// and local opened-item filtering. Never inferred from root or peer bytes.
    pub residence_selector: Option<crate::sync::SyncSelector>,
    /// Federation principal/grant supplied by the authenticated transport host.
    /// Never inferred from `auth_token` or untrusted CRDT peer ids.
    pub federation_peer: Option<crate::sync::federation_burst::FederationPeer>,
    /// Explicit role for selector UPDATE frames on a bound federation lane.
    pub federation_admission_role: crate::sync::FederationAdmissionRole,
    /// WebSocket server URL (e.g., "wss://user-{id}.fly.dev/ws").
    pub server_url: String,
    /// Legacy bearer-only token. A production host requires `transport_credential`.
    pub auth_token: String,
    /// Logged owner-grade slip and holder key for the `/ws` upgrade.
    pub transport_credential: Option<SyncTransportCredential>,
    /// Opt in to this configured server as the NOTE admission authority.
    /// Must be a MAC-verified actor-bound slip with core:read,core:write and jti.
    /// Only TLS or loopback URLs are accepted for this lane.
    pub note_session: Option<NoteSyncSession>,
    /// `None` on the home node means sync all worlds; `Some(worlds)` follows
    /// only the named worlds. The device default follows none until selected.
    pub followed_worlds: Option<Vec<crate::EntityId>>,
    /// Host-owned MACRO candidate feed. Its updates, not WebSocket liveness,
    /// cause the connection to persist a new home-node designation.
    pub home_node_topology: Option<crate::sync::connection::HomeNodeTopology>,
    /// Host-owned endpoint of the elected home for residence reads (index,
    /// first touch, promotion, search). Absent, `server_url` is the home.
    pub residence_home_route: Option<ResidenceHomeRoute>,
    /// Number of default windows to sync (current + previous). Default: 2.
    pub default_window_count: u8,
    /// Node proposal tick interval. Busy writers still flush every tick. Default: 50ms.
    pub sync_debounce_ms: u32,
    /// Maximum reconnection backoff delay. Default: 60s.
    pub reconnect_backoff_max_ms: u32,
    /// Initial reconnection delay. Default: 1s.
    pub reconnect_initial_ms: u32,
    /// Ephemeral state inactivity timeout in milliseconds. Default: 30s.
    pub ephemeral_timeout_ms: i64,
    /// A carrier to the home other than TCP to `server_url`, such as the
    /// paired home machine's mesh connection (OF-535). The upgrade still
    /// names `server_url`, and every slip and machine proof is the same.
    pub mesh_dialer: Option<std::sync::Arc<dyn crate::sync::SyncDialer>>,
    /// The authority checkpoint pin this machine's owner-authorized pairing
    /// returned (OF-469), never one the home hands over. Until this vault has
    /// adopted a checkpoint, each authority catch-up first fetches the image
    /// the pin names from the home and adopts it, then folds the tail.
    pub authority_checkpoint_pin: Option<crate::authority::AuthorityCheckpointPin>,
}

impl Default for SyncClientConfig {
    fn default() -> Self {
        Self {
            residence_mode: SyncResidenceMode::Opened,
            residence_selector: None,
            federation_peer: None,
            federation_admission_role: crate::sync::FederationAdmissionRole::Guest,
            server_url: String::new(),
            auth_token: String::new(),
            transport_credential: None,
            note_session: None,
            followed_worlds: Some(Vec::new()),
            home_node_topology: None,
            residence_home_route: None,
            default_window_count: 2,
            sync_debounce_ms: 50,
            reconnect_backoff_max_ms: 60_000,
            reconnect_initial_ms: 1_000,
            ephemeral_timeout_ms: 30_000,
            mesh_dialer: None,
            authority_checkpoint_pin: None,
        }
    }
}

/// Where residence reads go: the elected home's WebSocket endpoint, which
/// the host that owns the topology resolves and republishes on a change.
/// Socket loss never moves it; nothing here broadcasts to other machines.
#[derive(Debug, Clone)]
pub struct ResidenceHomeRoute {
    endpoint: std::sync::Arc<tokio::sync::watch::Sender<Option<String>>>,
}

impl ResidenceHomeRoute {
    #[must_use]
    pub fn new(endpoint: Option<String>) -> Self {
        Self {
            endpoint: std::sync::Arc::new(tokio::sync::watch::channel(endpoint).0),
        }
    }

    /// Publish the elected home's endpoint, or `None` to fall back to the
    /// configured sync server.
    pub fn publish(&self, endpoint: Option<String>) {
        self.endpoint.send_replace(endpoint);
    }

    /// The endpoint residence reads use now.
    #[must_use]
    pub fn current(&self) -> Option<String> {
        self.endpoint.borrow().clone()
    }
}

impl SyncClientConfig {
    /// The endpoint residence RPCs dial: the elected home when the host
    /// routes one, else the configured sync server.
    #[must_use]
    pub fn residence_url(&self) -> String {
        self.residence_home_route
            .as_ref()
            .and_then(ResidenceHomeRoute::current)
            .unwrap_or_else(|| self.server_url.clone())
    }
}

/// A logged slip and its throwaway holder key for each WebSocket upgrade.
/// The key is not an enrolled device authority; the host verifies the slip.
#[derive(Clone)]
pub struct SyncTransportCredential {
    token: String,
    key: ed25519_dalek::SigningKey,
}
impl SyncTransportCredential {
    pub fn new(token: String, key: ed25519_dalek::SigningKey) -> Self {
        Self { token, key }
    }

    /// Proves the slip on a WebSocket upgrade with a fresh holder signature.
    /// Each upgrade has its own nonce, so a proof cannot be replayed. An
    /// enrolled install also names its machine, signed over the same proof.
    /// Returns the proof, which the home's answer must bind.
    pub(in crate::sync) fn sign_upgrade(
        &self,
        vault: &crate::Vault,
        timestamp: u64,
        request: &mut tokio_tungstenite::tungstenite::handshake::client::Request,
    ) -> Result<crate::sync::home_proof::UpgradeBinding, &'static str> {
        use ed25519_dalek::Signer;
        use tokio_tungstenite::tungstenite::http::header::AUTHORIZATION;

        let slip = crate::authority::CapabilitySlip::from_token(&self.token)
            .map_err(|_| "Sync transport slip is invalid")?;
        if slip.claims.binding_key != self.key.verifying_key().to_bytes() {
            return Err("Sync transport holder key does not match slip");
        }
        let nonce = crate::EntityId::now().to_hex();
        let challenge = format!("oneiron-request:{timestamp}:{nonce}");
        let signature: String = self
            .key
            .sign(
                &slip
                    .binding_transcript(challenge.as_bytes())
                    .map_err(|_| "Sync transport binding transcript is invalid")?,
            )
            .to_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        request.headers_mut().insert(
            AUTHORIZATION,
            format!("Bearer {}", self.token)
                .parse()
                .map_err(|_| "Sync transport token is not a valid header")?,
        );
        request.headers_mut().insert(
            "x-oneiron-binding",
            serde_json::json!({"timestamp":timestamp,"nonce":nonce,"signature":signature})
                .to_string()
                .parse()
                .map_err(|_| "Sync transport proof is not a valid header")?,
        );
        // A machine that cannot name itself syncs as an unknown destination.
        if let Ok(Some((machine, proof))) =
            vault.machine_connection_proof(&self.token, timestamp, &nonce)
            && let Ok(value) = crate::authority::machine_proof_header_value(machine, &proof).parse()
        {
            request
                .headers_mut()
                .insert(crate::authority::MACHINE_PROOF_HEADER, value);
        }
        Ok(crate::sync::home_proof::UpgradeBinding {
            token: self.token.clone(),
            timestamp,
            nonce,
        })
    }
}
impl SyncTransportCredential {
    /// The headers of a removed member's leave-notice request
    /// (`POST /v1/shared/left-notices`, OF-158): the slip, revoked or not, in
    /// `x-oneiron-left-slip`, and a fresh holder proof over the standard
    /// request challenge in `x-oneiron-binding`.
    pub(in crate::sync) fn left_notice_headers(
        &self,
        timestamp: u64,
    ) -> Result<[(&'static str, String); 2], &'static str> {
        use ed25519_dalek::Signer;

        let slip = crate::authority::CapabilitySlip::from_token(&self.token)
            .map_err(|_| "Sync transport slip is invalid")?;
        if slip.claims.binding_key != self.key.verifying_key().to_bytes() {
            return Err("Sync transport holder key does not match slip");
        }
        let nonce = crate::EntityId::now().to_hex();
        let challenge = format!("oneiron-request:{timestamp}:{nonce}");
        let signature: String = self
            .key
            .sign(
                &slip
                    .binding_transcript(challenge.as_bytes())
                    .map_err(|_| "Sync transport binding transcript is invalid")?,
            )
            .to_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        Ok([
            ("x-oneiron-left-slip", self.token.clone()),
            (
                "x-oneiron-binding",
                serde_json::json!({"timestamp":timestamp,"nonce":nonce,"signature":signature})
                    .to_string(),
            ),
        ])
    }
}

impl std::fmt::Debug for SyncTransportCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SyncTransportCredential([redacted])")
    }
}

/// An actor credential for the explicit NOTE authority lane: the slip token
/// and the holder's signing key, whose public half is the slip's binding key.
#[derive(Clone)]
pub struct NoteSyncSession {
    token: String,
    key: ed25519_dalek::SigningKey,
}
impl NoteSyncSession {
    pub fn new(token: String, key: ed25519_dalek::SigningKey) -> Self {
        Self { token, key }
    }
    pub(super) fn token(&self) -> &str {
        &self.token
    }
    pub(super) fn key(&self) -> &ed25519_dalek::SigningKey {
        &self.key
    }
}
impl std::fmt::Debug for NoteSyncSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("NoteSyncSession([redacted])")
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
    /// A window replacement could not keep this device's value of these keys: each changed here
    /// and on the server, each unseen by the other, below the window's own root. The window now
    /// holds the server's value; each conflict carries the one this device held.
    ReplacementConflicts {
        window_key: String,
        conflicts: Vec<crate::sync::window::ReplacementConflict>,
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
    /// Inbound bytes are durably retained, not materialized or discarded.
    FederationDeferred {
        window_key: String,
        request_id: [u8; 32],
        inputs: crate::llm::NormalizedBurstInputs,
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
///
/// Production reads and writes go through the typed `ROOT_SNAPSHOT` table
/// (`crate::sync::window_rows`); this raw string stays only for this
/// module's own tests.
#[cfg(test)]
pub(super) const KEY_ROOT_DOC: &str = "d:root";

/// This device's CRDT client id (u64 LE, 8 bytes) — minted once, stable per
/// install. The mint lives in `crate::identity` (ONE-1140, OD-2); this
/// test-side literal pins the row key independently of that module.
#[cfg(test)]
pub(super) const KEY_CLIENT_ID: &str = "m:client_id";

/// `svf:*` byte meaning "the persisted `sv:*` reflects the full doc state".
pub(super) const SVF_FRESH: u8 = 1;
