//! Typed Context Board render projections.

use crate::run_tree::{RunTreeNode, RunTreeStatus};

/// AGENTS row lane.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentLane {
    Child,
    Peer,
}

impl AgentLane {
    /// Stable structural token for the lane.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Child => "child",
            Self::Peer => "peer",
        }
    }
}

/// One collapsed AGENTS row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentRow {
    pub id: String,
    pub lane: AgentLane,
    pub line: String,
    pub harness_label: Option<String>,
}

/// Collapsed AGENTS section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentsSection {
    pub rows: Vec<AgentRow>,
}

/// One present child agent projected from M8 driver state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChildAgentPresence {
    pub id: String,
    pub status: RunTreeStatus,
}

impl ChildAgentPresence {
    /// Present a running child from the M8 driver run-tree. Returns None for
    /// terminal nodes; the section shows who is working here now.
    #[must_use]
    pub fn from_run_tree_node(node: &RunTreeNode) -> Option<ChildAgentPresence> {
        if node.worker_kind != crate::agent_dispatch::AGENT_DISPATCH_ATTEMPT_TYPE {
            return None;
        }

        match node.status {
            RunTreeStatus::Completed | RunTreeStatus::Failed | RunTreeStatus::Cancelled => None,
            RunTreeStatus::Queued | RunTreeStatus::Running | RunTreeStatus::Paused => {
                // Prefer the per-agent handle; the attempt id is the stable fallback.
                Some(ChildAgentPresence {
                    id: node
                        .agent_id
                        .as_deref()
                        .filter(|id| !id.is_empty())
                        .map(str::to_owned)
                        .unwrap_or_else(|| node.attempt_id.clone()),
                    status: node.status,
                })
            }
        }
    }
}

/// Registry-populated peer-presence view; identity and registry storage remain upstream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerPresence {
    pub actor_handle: String,
    pub harness_label: String,
    pub last_seen: Option<u64>,
}

/// Renders provided agent presence into stable, collapsed rows.
#[must_use]
pub fn render_agents_section(
    children: &[ChildAgentPresence],
    peers: &[PeerPresence],
) -> AgentsSection {
    let mut rows = Vec::with_capacity(children.len() + peers.len());

    rows.extend(children.iter().map(|child| AgentRow {
        id: child.id.clone(),
        lane: AgentLane::Child,
        line: format!(
            "{} {}",
            one_line_token(&child.id),
            one_line_token(status_token(child.status))
        ),
        harness_label: None,
    }));
    rows.extend(peers.iter().map(|peer| AgentRow {
        id: peer.actor_handle.clone(),
        lane: AgentLane::Peer,
        line: format!(
            "{} {}",
            one_line_token(&peer.actor_handle),
            one_line_token(&peer.harness_label)
        ),
        harness_label: Some(peer.harness_label.clone()),
    }));

    AgentsSection { rows }
}

/// Collapse control characters so a rendered row is always one physical line.
fn one_line_token(s: &str) -> String {
    s.chars()
        .map(|character| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        })
        .collect()
}

const fn status_token(status: RunTreeStatus) -> &'static str {
    match status {
        RunTreeStatus::Queued => "queued",
        RunTreeStatus::Running => "running",
        RunTreeStatus::Paused => "paused",
        RunTreeStatus::Completed => "completed",
        RunTreeStatus::Failed => "failed",
        RunTreeStatus::Cancelled => "cancelled",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent_dispatch::AGENT_DISPATCH_ATTEMPT_TYPE;
    use crate::run_tree::{RunTreeStatus, RunTreeTimestamps};

    fn child(id: &str) -> ChildAgentPresence {
        ChildAgentPresence {
            id: id.to_owned(),
            status: RunTreeStatus::Running,
        }
    }

    fn peer(actor_handle: &str) -> PeerPresence {
        PeerPresence {
            actor_handle: actor_handle.to_owned(),
            harness_label: "claude-code".to_owned(),
            last_seen: Some(1),
        }
    }

    fn run_tree_node(agent_id: Option<&str>, status: RunTreeStatus) -> RunTreeNode {
        run_tree_node_with_worker_kind(agent_id, status, AGENT_DISPATCH_ATTEMPT_TYPE)
    }

    fn run_tree_node_with_worker_kind(
        agent_id: Option<&str>,
        status: RunTreeStatus,
        worker_kind: &str,
    ) -> RunTreeNode {
        RunTreeNode {
            attempt_id: "attempt_a".to_owned(),
            run_id: None,
            parent_id: None,
            worker_kind: worker_kind.to_owned(),
            agent_id: agent_id.map(str::to_owned),
            status,
            timestamps: RunTreeTimestamps {
                created_at: 1,
                updated_at: 2,
            },
            failure: None,
            events: Vec::new(),
            children: Vec::new(),
        }
    }

    #[test]
    fn renders_children_and_peers_as_one_line_rows() {
        let children = [child("child_a"), child("child_b")];
        let peers = [peer("cc-main"), peer("cc-second")];

        let section = render_agents_section(&children, &peers);

        assert_eq!(section.rows.len(), 4);
        let non_empty_lines = section
            .rows
            .iter()
            .filter(|row| !row.line.is_empty())
            .count();
        assert_eq!(non_empty_lines, 4);
        let one_line_rows = section
            .rows
            .iter()
            .filter(|row| row.line.lines().count() == 1)
            .count();
        assert_eq!(one_line_rows, 4);

        let child_rows: Vec<&AgentRow> = section
            .rows
            .iter()
            .filter(|row| row.lane == AgentLane::Child)
            .collect();
        assert_eq!(child_rows.len(), 2);
        let mut child_ids: Vec<&str> = child_rows.iter().map(|row| row.id.as_str()).collect();
        child_ids.sort_unstable();
        assert_eq!(child_ids, ["child_a", "child_b"]);
        let child_rows_without_labels = child_rows
            .iter()
            .filter(|row| row.harness_label.is_none())
            .count();
        assert_eq!(child_rows_without_labels, 2);

        let peer_rows: Vec<&AgentRow> = section
            .rows
            .iter()
            .filter(|row| row.lane == AgentLane::Peer)
            .collect();
        assert_eq!(peer_rows.len(), 2);
        let mut peer_ids: Vec<&str> = peer_rows.iter().map(|row| row.id.as_str()).collect();
        peer_ids.sort_unstable();
        assert_eq!(peer_ids, ["cc-main", "cc-second"]);
        let peer_rows_with_labels = peer_rows
            .iter()
            .filter(|row| row.harness_label.as_deref() == Some("claude-code"))
            .count();
        assert_eq!(peer_rows_with_labels, 2);
    }

    #[test]
    fn control_characters_cannot_split_rendered_rows() {
        let children = [child("child_a\nspoof")];
        let peers = [PeerPresence {
            actor_handle: "cc-main\rspoof".to_owned(),
            harness_label: "claude\ncode".to_owned(),
            last_seen: Some(1),
        }];

        let section = render_agents_section(&children, &peers);

        assert_eq!(section.rows.len(), 2);
        let non_empty_rows = section
            .rows
            .iter()
            .filter(|row| !row.line.is_empty())
            .count();
        assert_eq!(non_empty_rows, 2);
        let one_line_rows = section
            .rows
            .iter()
            .filter(|row| row.line.lines().count() == 1)
            .count();
        assert_eq!(one_line_rows, 2);
        assert_eq!(section.rows[0].id, "child_a\nspoof");
        assert_eq!(section.rows[1].id, "cc-main\rspoof");
        assert_eq!(
            section.rows[1].harness_label.as_deref(),
            Some("claude\ncode")
        );
    }

    #[test]
    fn peer_identity_is_connection_keyed() {
        let section = render_agents_section(&[], &[peer("cc-main"), peer("cc-second")]);

        assert_eq!(section.rows.len(), 2);
        assert_ne!(section.rows[0].id, section.rows[1].id);
        let exact_labels = section
            .rows
            .iter()
            .filter(|row| row.harness_label.as_deref() == Some("claude-code"))
            .count();
        assert_eq!(exact_labels, 2);
    }

    #[test]
    fn bridge_discriminates_driver_state() {
        let queued = run_tree_node(Some("child_q"), RunTreeStatus::Queued);
        let running = run_tree_node(Some("child_a"), RunTreeStatus::Running);
        let paused = run_tree_node(Some("child_p"), RunTreeStatus::Paused);
        let completed = run_tree_node(Some("child_b"), RunTreeStatus::Completed);
        let failed = run_tree_node(Some("child_f"), RunTreeStatus::Failed);
        let cancelled = run_tree_node(Some("child_c"), RunTreeStatus::Cancelled);

        let presence = ChildAgentPresence::from_run_tree_node(&running);
        assert_eq!(
            presence.as_ref().map(|child| child.id.as_str()),
            Some("child_a")
        );
        assert_eq!(
            presence.map(|child| child.status),
            Some(RunTreeStatus::Running)
        );
        assert_eq!(ChildAgentPresence::from_run_tree_node(&completed), None);

        let lifecycle_presences = [
            ChildAgentPresence::from_run_tree_node(&queued),
            ChildAgentPresence::from_run_tree_node(&running),
            ChildAgentPresence::from_run_tree_node(&paused),
            ChildAgentPresence::from_run_tree_node(&completed),
            ChildAgentPresence::from_run_tree_node(&failed),
            ChildAgentPresence::from_run_tree_node(&cancelled),
        ];
        let present_count = lifecycle_presences
            .iter()
            .filter(|presence| presence.is_some())
            .count();
        assert_eq!(present_count, 3);
        let absent_count = lifecycle_presences
            .iter()
            .filter(|presence| presence.is_none())
            .count();
        assert_eq!(absent_count, 3);
        assert_eq!(
            lifecycle_presences[0]
                .as_ref()
                .map(|child| child.id.as_str()),
            Some("child_q")
        );
        assert_eq!(
            lifecycle_presences[1]
                .as_ref()
                .map(|child| child.id.as_str()),
            Some("child_a")
        );
        assert_eq!(
            lifecycle_presences[2]
                .as_ref()
                .map(|child| child.id.as_str()),
            Some("child_p")
        );
        assert_eq!(lifecycle_presences[3], None);
        assert_eq!(lifecycle_presences[4], None);
        assert_eq!(lifecycle_presences[5], None);

        let non_agent =
            run_tree_node_with_worker_kind(Some("fake_child"), RunTreeStatus::Running, "dreamer");
        assert_eq!(ChildAgentPresence::from_run_tree_node(&non_agent), None);

        let missing_id = run_tree_node(None, RunTreeStatus::Running);
        let missing_id_presence = ChildAgentPresence::from_run_tree_node(&missing_id);
        assert_eq!(
            missing_id_presence.as_ref().map(|child| child.id.as_str()),
            Some("attempt_a")
        );
        assert_eq!(
            missing_id_presence.map(|child| child.status),
            Some(RunTreeStatus::Running)
        );

        let blank_id = run_tree_node(Some(""), RunTreeStatus::Running);
        let blank_id_presence = ChildAgentPresence::from_run_tree_node(&blank_id);
        assert_eq!(
            blank_id_presence.as_ref().map(|child| child.id.as_str()),
            Some("attempt_a")
        );
        assert_eq!(
            blank_id_presence.map(|child| child.status),
            Some(RunTreeStatus::Running)
        );
    }

    #[test]
    fn empty_inputs_render_empty_section() {
        let section = render_agents_section(&[], &[]);

        assert_eq!(section.rows.len(), 0);
    }
}
