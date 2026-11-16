//! Moved from `crates/oneiron/src/sync/mesh_path.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// Which side dialed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum MeshPathDirection {
    /// A peer dialed this machine.
    Inbound,
    /// This machine dialed a peer.
    Outbound,
}

/// How the attempt ended at admission.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum MeshPathOutcome {
    /// The handshake and the paired-machine grant admitted it.
    Admitted,
    /// The roster or the grant refused it.
    Refused,
    /// The dial never reached an authenticated peer.
    Failed,
}

/// The network paths a connection had open: direct IP, a relay, both, or
/// none.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum MeshPathKind {
    Direct,
    Relayed,
    Mixed,
    None,
}

/// One mesh connection's path receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MeshPathReceipt {
    /// The receipt's id; empty until its first write mints one.
    pub id: String,
    pub direction: MeshPathDirection,
    pub outcome: MeshPathOutcome,
    /// The MACHINE (hex) the roster named for the peer, when it named one.
    pub machine: Option<String>,
    /// The peer's endpoint key (hex): the one the handshake authenticated,
    /// or the roster's key for a dial that reached no peer.
    pub endpoint_key: Option<String>,
    /// The ALPN the connection asked for.
    pub alpn: String,
    pub opened_at_ms: u64,
    /// When the connection closed; `None` while it is open and on an attempt
    /// that was never admitted.
    pub closed_at_ms: Option<u64>,
    /// The paths open at admission or refusal.
    pub paths: MeshPathKind,
    /// Whether a direct path carried the connection's data at any point.
    pub used_direct: bool,
    /// Whether a relay path carried the connection's data at any point.
    pub used_relay: bool,
    /// The last direct address that carried data.
    pub direct_addr: Option<String>,
    /// The last relay that carried data.
    pub relay_url: Option<String>,
    /// Why it was refused, failed or closed.
    pub detail: Option<String>,
    /// The attempts this receipt stands for: 1 for an admitted connection; on
    /// a refusal, it and every refusal folded since the last one written.
    pub attempts: u64,
}

impl MeshPathReceipt {
    /// A receipt for an attempt on `alpn` opened now, with no path noted yet.
    #[must_use]
    pub fn new(direction: MeshPathDirection, outcome: MeshPathOutcome, alpn: &[u8]) -> Self {
        Self {
            id: String::new(),
            direction,
            outcome,
            machine: None,
            endpoint_key: None,
            alpn: String::from_utf8_lossy(alpn).into_owned(),
            opened_at_ms: oneiron_base::unix_millis_now(),
            closed_at_ms: None,
            paths: MeshPathKind::None,
            used_direct: false,
            used_relay: false,
            direct_addr: None,
            relay_url: None,
            detail: None,
            attempts: 1,
        }
    }
}

/// The most receipts one read returns.
pub const MESH_PATH_RECEIPTS_READ_MAX: usize = 1024;
