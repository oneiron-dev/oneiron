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
    pub label: Option<String>,
}

impl ChildAgentPresence {
    /// Presents a running M8 agent-dispatch subagent; row identity is its per-spawn
    /// attempt id, while its AgentDefinition label (`agent_id`) is optional display text.
    /// Returns `None` for non-agent-dispatch attempts and terminal nodes because the
    /// section shows children working here now.
    #[must_use]
    pub fn from_run_tree_node(node: &RunTreeNode) -> Option<ChildAgentPresence> {
        if node.worker_kind != crate::agent_dispatch::AGENT_DISPATCH_ATTEMPT_TYPE {
            return None;
        }

        match node.status {
            RunTreeStatus::Completed | RunTreeStatus::Failed | RunTreeStatus::Cancelled => None,
            RunTreeStatus::Queued | RunTreeStatus::Running | RunTreeStatus::Paused => {
                Some(ChildAgentPresence {
                    id: node.attempt_id.clone(),
                    status: node.status,
                    label: node
                        .agent_id
                        .as_deref()
                        .map(str::trim)
                        .filter(|label| !label.is_empty())
                        .map(str::to_owned),
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
        line: match child.label.as_deref() {
            Some(label) => format!(
                "{} {} {}",
                one_line_token(&child.id),
                one_line_token(label),
                one_line_token(status_token(child.status))
            ),
            None => format!(
                "{} {}",
                one_line_token(&child.id),
                one_line_token(status_token(child.status))
            ),
        },
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
            label: None,
        }
    }

    fn peer(actor_handle: &str) -> PeerPresence {
        PeerPresence {
            actor_handle: actor_handle.to_owned(),
            harness_label: "claude-code".to_owned(),
            last_seen: Some(1),
        }
    }

    fn run_tree_node(
        attempt_id: &str,
        agent_id: Option<&str>,
        status: RunTreeStatus,
    ) -> RunTreeNode {
        run_tree_node_with_worker_kind(attempt_id, agent_id, status, AGENT_DISPATCH_ATTEMPT_TYPE)
    }

    fn run_tree_node_with_worker_kind(
        attempt_id: &str,
        agent_id: Option<&str>,
        status: RunTreeStatus,
        worker_kind: &str,
    ) -> RunTreeNode {
        RunTreeNode {
            attempt_id: attempt_id.to_owned(),
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
        let children_without_labels = children
            .iter()
            .filter(|child| child.label.is_none())
            .count();
        assert_eq!(children_without_labels, 2);
        let child_rows_without_labels = child_rows
            .iter()
            .filter(|row| row.harness_label.is_none())
            .count();
        assert_eq!(child_rows_without_labels, 2);
        let child_a = child_rows
            .iter()
            .find(|row| row.id == "child_a")
            .expect("child_a row must be rendered");
        assert_eq!(child_a.line, "child_a running");
        let child_b = child_rows
            .iter()
            .find(|row| row.id == "child_b")
            .expect("child_b row must be rendered");
        assert_eq!(child_b.line, "child_b running");

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
        let cc_main = peer_rows
            .iter()
            .find(|row| row.id == "cc-main")
            .expect("cc-main row must be rendered");
        assert_eq!(cc_main.line, "cc-main claude-code");
        let cc_second = peer_rows
            .iter()
            .find(|row| row.id == "cc-second")
            .expect("cc-second row must be rendered");
        assert_eq!(cc_second.line, "cc-second claude-code");
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
        assert_eq!(section.rows[0].harness_label, None);
        assert_eq!(section.rows[0].line, "child_a spoof running");
        assert_eq!(section.rows[1].id, "cc-main\rspoof");
        assert_eq!(
            section.rows[1].harness_label.as_deref(),
            Some("claude\ncode")
        );
        assert_eq!(section.rows[1].line, "cc-main spoof claude code");
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
        let queued = run_tree_node("attempt_q", Some("child_q"), RunTreeStatus::Queued);
        let running = run_tree_node("attempt_a", Some("child_a"), RunTreeStatus::Running);
        let paused = run_tree_node("attempt_p", Some("child_p"), RunTreeStatus::Paused);
        let completed = run_tree_node("attempt_b", Some("child_b"), RunTreeStatus::Completed);
        let failed = run_tree_node("attempt_f", Some("child_f"), RunTreeStatus::Failed);
        let cancelled = run_tree_node("attempt_c", Some("child_c"), RunTreeStatus::Cancelled);

        let presence = ChildAgentPresence::from_run_tree_node(&running);
        assert_eq!(
            presence.as_ref().map(|child| child.id.as_str()),
            Some("attempt_a")
        );
        assert_eq!(
            presence.as_ref().and_then(|child| child.label.as_deref()),
            Some("child_a")
        );
        assert_eq!(
            presence.as_ref().map(|child| child.status),
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
        let present_children: Vec<(&str, Option<&str>, RunTreeStatus)> = lifecycle_presences
            .iter()
            .filter_map(|presence| presence.as_ref())
            .map(|child| (child.id.as_str(), child.label.as_deref(), child.status))
            .collect();
        assert_eq!(
            present_children,
            [
                ("attempt_q", Some("child_q"), RunTreeStatus::Queued),
                ("attempt_a", Some("child_a"), RunTreeStatus::Running),
                ("attempt_p", Some("child_p"), RunTreeStatus::Paused),
            ]
        );
        assert_eq!(lifecycle_presences[3], None);
        assert_eq!(lifecycle_presences[4], None);
        assert_eq!(lifecycle_presences[5], None);

        let non_agent = run_tree_node_with_worker_kind(
            "attempt_fake",
            Some("fake_child"),
            RunTreeStatus::Running,
            "dreamer",
        );
        assert_eq!(ChildAgentPresence::from_run_tree_node(&non_agent), None);

        let missing_label = run_tree_node("attempt_missing", None, RunTreeStatus::Running);
        let missing_label_presence = ChildAgentPresence::from_run_tree_node(&missing_label);
        assert_eq!(
            missing_label_presence
                .as_ref()
                .map(|child| child.id.as_str()),
            Some("attempt_missing")
        );
        assert_eq!(
            missing_label_presence
                .as_ref()
                .and_then(|child| child.label.as_deref()),
            None
        );

        let blank_label = run_tree_node("attempt_blank", Some("   "), RunTreeStatus::Running);
        let blank_label_presence = ChildAgentPresence::from_run_tree_node(&blank_label);
        assert_eq!(
            blank_label_presence.as_ref().map(|child| child.id.as_str()),
            Some("attempt_blank")
        );
        assert_eq!(
            blank_label_presence
                .as_ref()
                .and_then(|child| child.label.as_deref()),
            None
        );
    }

    #[test]
    fn child_identity_is_per_spawn_not_definition_label() {
        let nodes = [
            run_tree_node("attempt_1", Some("researcher"), RunTreeStatus::Running),
            run_tree_node("attempt_2", Some("researcher"), RunTreeStatus::Running),
        ];
        let presences: Vec<ChildAgentPresence> = nodes
            .iter()
            .filter_map(ChildAgentPresence::from_run_tree_node)
            .collect();

        assert_eq!(presences.len(), 2);
        let ids: Vec<&str> = presences.iter().map(|child| child.id.as_str()).collect();
        assert_eq!(ids, ["attempt_1", "attempt_2"]);
        assert_ne!(ids[0], ids[1]);
        let mut distinct_ids = ids.clone();
        distinct_ids.sort_unstable();
        distinct_ids.dedup();
        assert_eq!(distinct_ids.len(), 2);
        let labels: Vec<Option<&str>> = presences
            .iter()
            .map(|child| child.label.as_deref())
            .collect();
        assert_eq!(labels, [Some("researcher"), Some("researcher")]);

        let section = render_agents_section(&presences, &[]);

        assert_eq!(section.rows.len(), 2);
        let rendered_ids: Vec<&str> = section.rows.iter().map(|row| row.id.as_str()).collect();
        assert_eq!(rendered_ids, ["attempt_1", "attempt_2"]);
        let rendered_lines: Vec<&str> = section.rows.iter().map(|row| row.line.as_str()).collect();
        assert_eq!(
            rendered_lines,
            [
                "attempt_1 researcher running",
                "attempt_2 researcher running"
            ]
        );
        let mut distinct_lines = rendered_lines.clone();
        distinct_lines.sort_unstable();
        distinct_lines.dedup();
        assert_eq!(distinct_lines.len(), 2);
    }

    #[test]
    fn empty_inputs_render_empty_section() {
        let section = render_agents_section(&[], &[]);

        assert_eq!(section.rows.len(), 0);
    }
}
