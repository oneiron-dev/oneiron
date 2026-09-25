//! AGENTS consult metering rows. Rendering is never an admission input.

use super::{AgentLane, AgentRow, one_line_token};
use crate::outbound_chokepoint::{FanoutEstimate, FanoutPathology};

pub(crate) fn fanout_agent_rows(
    correlation: &str,
    estimate: &FanoutEstimate,
    pathology: Option<&FanoutPathology>,
    paused: bool,
    denied: bool,
) -> Vec<AgentRow> {
    let id = format!("fanout:{}", one_line_token(correlation));
    let state = if denied {
        "denied_parked"
    } else if paused {
        "paused"
    } else {
        "dispatched"
    };
    let mut rows = vec![AgentRow {
        id: id.clone(),
        lane: AgentLane::Fanout,
        line: format!("{id} consults={} {state}", estimate.total_count),
        harness_label: None,
    }];
    rows.extend(estimate.per_peer.iter().map(|(peer, count)| AgentRow {
        id: format!("{id}:peer:{peer}"),
        lane: AgentLane::Fanout,
        line: format!("{id} peer={} consults={count}", one_line_token(peer)),
        harness_label: None,
    }));
    if let Some(pathology) = pathology {
        let evidence = match pathology {
            FanoutPathology::ConsultCycle { peer_path } => {
                // One hop per row avoids exceeding the board byte bound for
                // deep consult chains; no hidden truncation of cycle evidence.
                for (index, peer) in peer_path.iter().enumerate() {
                    rows.push(AgentRow {
                        id: format!("{id}:cycle:{index}"),
                        lane: AgentLane::Fanout,
                        line: format!("{id} cycle_hop={index} peer={}", one_line_token(peer)),
                        harness_label: None,
                    });
                }
                "consult_cycle".to_owned()
            }
            FanoutPathology::PerPeerRateSpike {
                peer_ref,
                projected_count,
                spike_at,
                window_secs,
            } => format!(
                "rate_spike peer={} projected={projected_count} spike_at={spike_at} window_secs={window_secs}",
                one_line_token(peer_ref)
            ),
        };
        rows.push(AgentRow {
            id: format!("{id}:pathology"),
            lane: AgentLane::Fanout,
            line: format!("{id} evidence={evidence}"),
            harness_label: None,
        });
    }
    rows
}
