//! Public fan-out governance inputs and observable outcomes.

use super::TaskCreateRateLimit;
use crate::agent_dispatch::FanoutStatement;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub use crate::outbound_chokepoint::FanoutApprovalMode as ConsultFanOutMode;

/// Vault-owned approval knobs. There is no per-peer budget by default.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsultFanOutPolicy {
    /// The exceptional-width check threshold. It only marks the check, which
    /// never holds; `mode` gates every fan-out at any width.
    pub approval_threshold: u32,
    pub mode: ConsultFanOutMode,
    /// Optional anomaly detector, not a spend cap. Crossings pause visibly.
    pub peer_rate: Option<ConsultFanOutRate>,
    /// The owner-authored actor request rate. Past it a fan-out still lands,
    /// and the first request past it in a window leaves an OF-520 check.
    /// Every fan-out of an actor counts against the vault's row; a scoped
    /// row's rate composes into its policy but does not move the check.
    pub create_rate: TaskCreateRateLimit,
}

impl Default for ConsultFanOutPolicy {
    fn default() -> Self {
        crate::gate::default_consult_fanout_policy()
    }
}

/// Optional per-peer rate evidence window.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsultFanOutRate {
    pub window_secs: u64,
    pub spike_at: u32,
}

/// A ruling on the exact digest the human saw. Denial parks; it never cancels.
/// On a width check, which held nothing, approve-once acknowledges it,
/// approve-and-remember acknowledges it and persists the receipted policy row
/// AUTO reads next time, and deny is refused.
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
    /// TASKS meter rows, generated from this same estimate, not re-metered.
    pub board_rows: Vec<FanoutMeterRow>,
    /// Stated before any TASK was minted and frozen with the run: counts,
    /// expected spend, the cap or none, and any width check. Never re-priced.
    pub statement: FanoutStatement,
}

/// Side-effect-free estimate of the counted consults in a submitted plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsultFanOutEstimate {
    pub total_count: u32,
    pub per_peer: BTreeMap<String, u32>,
    /// What admission would state, without a caller cap (none) and without
    /// the width check, which only admission classifies.
    pub statement: FanoutStatement,
}

/// Policy path supplied by an authenticated host for a frozen consult plan.
/// The vault level is implicit; each additional level names its parent.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsultFanOutScope {
    pub project_ref: Option<String>,
    pub subproject_ref: Option<String>,
    pub thread_ref: Option<String>,
}

/// One consult fan-out meter row: the run's counts per peer, its state, and
/// any pathology evidence. Rendering is never an admission input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FanoutMeterRow {
    pub id: String,
    pub line: String,
}

pub(crate) fn fanout_meter_rows(
    correlation: &str,
    estimate: &crate::outbound_chokepoint::FanoutEstimate,
    pathology: Option<&crate::outbound_chokepoint::FanoutPathology>,
    paused: bool,
    denied: bool,
) -> Vec<FanoutMeterRow> {
    let id = format!("fanout:{}", crate::context_board::one_line_token(correlation));
    let state = if denied {
        "denied_parked"
    } else if paused {
        "paused"
    } else {
        "dispatched"
    };
    let mut rows = vec![FanoutMeterRow {
        id: id.clone(),
        line: format!("{id} consults={} {state}", estimate.total_count),
    }];
    rows.extend(estimate.per_peer.iter().map(|(peer, count)| FanoutMeterRow {
        id: format!("{id}:peer:{peer}"),
        line: format!("{id} peer={} consults={count}", crate::context_board::one_line_token(peer)),
    }));
    if let Some(pathology) = pathology {
        let evidence = match pathology {
            crate::outbound_chokepoint::FanoutPathology::ConsultCycle { peer_path } => {
                // One hop per row avoids exceeding the board byte bound for
                // deep consult chains; no hidden truncation of cycle evidence.
                for (index, peer) in peer_path.iter().enumerate() {
                    rows.push(FanoutMeterRow {
                        id: format!("{id}:cycle:{index}"),
                        line: format!("{id} cycle_hop={index} peer={}", crate::context_board::one_line_token(peer)),
                    });
                }
                "consult_cycle".to_owned()
            }
            crate::outbound_chokepoint::FanoutPathology::PerPeerRateSpike {
                peer_ref,
                projected_count,
                spike_at,
                window_secs,
            } => format!(
                "rate_spike peer={} projected={projected_count} spike_at={spike_at} window_secs={window_secs}",
                crate::context_board::one_line_token(peer_ref)
            ),
        };
        rows.push(FanoutMeterRow {
            id: format!("{id}:pathology"),
            line: format!("{id} evidence={evidence}"),
        });
    }
    rows
}
