//! Public fan-out governance inputs and observable outcomes.

use crate::agent_dispatch::FanoutStatement;
use std::collections::BTreeMap;

pub use crate::outbound_chokepoint::FanoutApprovalMode as ConsultFanOutMode;

pub use crate::gate::consult_fanout_values::{ConsultFanOutPolicy, ConsultFanOutRate};

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

pub use crate::gate::consult_fanout_values::ConsultFanOutScope;

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
    let id = format!(
        "fanout:{}",
        crate::context_board::one_line_token(correlation)
    );
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
    rows.extend(
        estimate
            .per_peer
            .iter()
            .map(|(peer, count)| FanoutMeterRow {
                id: format!("{id}:peer:{peer}"),
                line: format!(
                    "{id} peer={} consults={count}",
                    crate::context_board::one_line_token(peer)
                ),
            }),
    );
    if let Some(pathology) = pathology {
        let evidence = match pathology {
            crate::outbound_chokepoint::FanoutPathology::ConsultCycle { peer_path } => {
                // One hop per row avoids exceeding the board byte bound for
                // deep consult chains; no hidden truncation of cycle evidence.
                for (index, peer) in peer_path.iter().enumerate() {
                    rows.push(FanoutMeterRow {
                        id: format!("{id}:cycle:{index}"),
                        line: format!(
                            "{id} cycle_hop={index} peer={}",
                            crate::context_board::one_line_token(peer)
                        ),
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
