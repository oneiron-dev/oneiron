//! Public fan-out governance inputs and observable outcomes.

use crate::context_board::AgentRow;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub use crate::outbound_chokepoint::FanoutApprovalMode as ConsultFanOutMode;

/// Vault-owned approval knobs. There is no per-peer budget by default.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsultFanOutPolicy {
    pub approval_threshold: u32,
    pub mode: ConsultFanOutMode,
    /// Optional anomaly detector, not a spend cap. Crossings pause visibly.
    pub peer_rate: Option<ConsultFanOutRate>,
}

impl Default for ConsultFanOutPolicy {
    fn default() -> Self {
        Self {
            approval_threshold: 25,
            mode: ConsultFanOutMode::Auto,
            peer_rate: None,
        }
    }
}

/// Optional per-peer rate evidence window.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsultFanOutRate {
    pub window_secs: u64,
    pub spike_at: u32,
}

/// A ruling on the exact digest the human saw. Denial parks; it never cancels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsultFanOutChoice {
    ApproveOnce,
    ApproveAndRemember,
    Deny,
}

/// Durable visible pause, returned instead of silently returning no tasks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsultFanOutPause {
    pub surface_ref: String,
    pub denied: bool,
}

/// Metering is returned for every run, including paused ones.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsultFanOutMeter {
    pub total_count: u32,
    pub per_peer: BTreeMap<String, u32>,
    pub plan_digest: [u8; 32],
    /// AGENTS rows, generated from this same estimate, not re-metered.
    pub board_rows: Vec<AgentRow>,
}
