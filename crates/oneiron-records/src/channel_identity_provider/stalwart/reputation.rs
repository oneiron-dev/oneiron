//! Moved from `crates/oneiron/src/channel_identity_provider/stalwart/reputation.rs` (lib split R3: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

/// There is intentionally no synthetic engagement or warmup-network source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeMailSignalSource {
    Postmaster,
    RealTraffic,
}

/// Cumulative counters for one identity from a host's verified report. Replies
/// and OOO responses are real inbound traffic, never generated warmup sends.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeMailReputationReport {
    pub observation_ref: String,
    pub evidence_ref: EntityId,
    pub source: NativeMailSignalSource,
    pub delivered: u64,
    pub bounces: u64,
    pub complaints: u64,
    pub spam_label_observations: u64,
    pub replies: u64,
    pub out_of_office: u64,
    /// Present only for an actual Postmaster report. Absence earns no
    /// attestation; a negative report never earns a graduation offer.
    pub postmaster_healthy: Option<bool>,
    pub observed_at: u64,
}
