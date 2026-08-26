//! AGENTS section projections — child agents and peer connections.

use super::one_line_token;
use crate::agent_run_status::{AgentRunStatus, project_agent_run_status_with_park};
use crate::run_tree::RunTreeNode;

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

/// Role token for a child that has agent-dispatch children of its own.
///
/// Crate-visible: `context_board`'s public surface is the curated re-export
/// list in its `mod.rs`, and the token's contract for outside readers is the
/// rendered `"lead"` / `"worker"` string itself.
pub(crate) const AGENT_ROLE_LEAD: &str = "lead";
/// Role token for a child with nothing under it.
pub(crate) const AGENT_ROLE_WORKER: &str = "worker";

/// A child's structural place in its own spawn subtree, as a rendered TOKEN.
///
/// Derived from the existing `RunTreeNode` mapping — it reads the shipped tree
/// rather than adding a second one, and it is a display label, never authority.
/// A child that spawned children of its own is leading; one that has not is
/// working. Deliberately a token rather than a new enum: the AGENTS row
/// vocabulary is rendered text, and this label rides it.
#[must_use]
pub(crate) fn agent_role_token(node: &RunTreeNode) -> &'static str {
    if node
        .children
        .iter()
        .any(|child| child.worker_kind == crate::agent_dispatch::AGENT_DISPATCH_ATTEMPT_TYPE)
    {
        AGENT_ROLE_LEAD
    } else {
        AGENT_ROLE_WORKER
    }
}

/// One present child agent projected from M8 driver state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChildAgentPresence {
    pub id: String,
    pub status: AgentRunStatus,
    pub label: Option<String>,
    /// Structural role rendered as a suffix for agents that lead descendants.
    pub role: String,
}

impl ChildAgentPresence {
    /// Presents a running M8 agent-dispatch subagent; row identity is its per-spawn
    /// attempt id, while its AgentDefinition label (`agent_id`) is optional display text.
    /// Returns `None` for non-agent-dispatch attempts and terminal nodes because the
    /// section shows children working here now.
    #[must_use]
    pub fn from_run_tree_node(node: &RunTreeNode) -> Option<ChildAgentPresence> {
        Self::from_run_tree_node_with_park(node, false)
    }

    #[must_use]
    pub fn from_run_tree_node_with_park(
        node: &RunTreeNode,
        is_parked: bool,
    ) -> Option<ChildAgentPresence> {
        if node.worker_kind != crate::agent_dispatch::AGENT_DISPATCH_ATTEMPT_TYPE {
            return None;
        }
        let status = project_agent_run_status_with_park(node.status, is_parked);
        if !status.is_live_presence() {
            return None;
        }
        Some(ChildAgentPresence {
            id: node.attempt_id.clone(),
            status,
            label: node
                .agent_id
                .as_deref()
                .map(str::trim)
                .filter(|label| !label.is_empty())
                .map(str::to_owned),
            role: agent_role_token(node).to_owned(),
        })
    }

    /// Every present descendant of `node`, itself included, in tree order.
    #[must_use]
    pub fn from_run_tree_branch(node: &RunTreeNode) -> Vec<ChildAgentPresence> {
        let mut presences = Vec::new();
        collect_branch_presence(node, &mut presences);
        presences
    }
}

fn collect_branch_presence(node: &RunTreeNode, out: &mut Vec<ChildAgentPresence>) {
    out.extend(ChildAgentPresence::from_run_tree_node(node));
    for child in &node.children {
        collect_branch_presence(child, out);
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
        line: {
            let mut line = match child.label.as_deref() {
                Some(label) => format!(
                    "{} {} {}",
                    one_line_token(&child.id),
                    one_line_token(label),
                    one_line_token(child.status.as_str())
                ),
                None => format!(
                    "{} {}",
                    one_line_token(&child.id),
                    one_line_token(child.status.as_str())
                ),
            };
            if child.role == AGENT_ROLE_LEAD {
                line.push(' ');
                line.push_str(AGENT_ROLE_LEAD);
            }
            line
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

#[cfg(test)]
mod tests {
    use super::super::test_support::{run_tree_node, run_tree_node_with_worker_kind};
    use super::*;
    use crate::run_tree::RunTreeStatus;

    #[test]
    fn paused_agent_dispatch_renders_needs_input_and_resume_renders_working() {
        use super::{ChildAgentPresence, render_agents_section};
        use crate::agent_dispatch::{AgentDispatchOutcome, AgentDispatcher};
        use crate::dreamer_runner::{DreamerRunnerStore, ParkDreamerAttempt};
        use crate::llm::{
            DurableStepContext, consume_trap_signal, open_trap, register_wait, send_trap_signal,
            trap_for_durable_wait, trap_park_owner,
        };
        use crate::{
            AttemptQueue, EdgeActorClass, EntityId, VaultConfig, WriteActor,
            code_run::SelfDurableWait, code_run::SelfDurableWaitReason, code_run::SelfEffect,
        };

        let (_dir, vault) = crate::test_util::open_test_vault_with(VaultConfig::device());
        let dispatcher = AgentDispatcher::new(&vault);
        let AgentDispatchOutcome::Dispatched(status) = dispatcher
            .dispatch_default_base(None, None, None, 1)
            .expect("dispatch")
        else {
            panic!("expected fresh dispatch")
        };
        let attempt_id = status.attempt.id;
        let step_hash = [0x71u8; 32];
        let subject = EntityId::from_bytes([0x42; 16]).expect("subject");
        vault
            .put_entity(
                &subject,
                crate::registry::ENTITY_TYPE_PERSON,
                crate::TimeRange { start: 1, end: 1 },
                1,
                b"agent subject",
            )
            .expect("subject entity");
        let wait = SelfDurableWait {
            wait_id: subject,
            effect: SelfEffect::AskHuman,
            reason: SelfDurableWaitReason::HumanInput,
            prompt: Some("decide".to_owned()),
        };
        let ctx = DurableStepContext {
            vault: &vault,
            attempt_id,
            run_id: Some("agent-run".to_owned()),
            envelope_actor: WriteActor::new(subject, EdgeActorClass::Agent),
            subject,
            deadline: None,
            now_ms: 1,
        };
        let trap = open_trap(
            &vault,
            &ctx,
            trap_for_durable_wait(&wait, step_hash),
            step_hash,
            "human response",
        )
        .expect("open trap");
        let queue = AttemptQueue::new(&vault);
        queue
            .claim(crate::attempt_queue::ClaimAttempt {
                lease_owner: "agent-worker".to_owned(),
                now: 2,
            })
            .expect("claim dispatched attempt");
        let runner = DreamerRunnerStore::new(&vault);
        runner
            .park_attempt(ParkDreamerAttempt {
                attempt_id,
                reason: "human response".to_owned(),
                park_owner: trap_park_owner(&trap.trap_claim_id),
                now: 1,
            })
            .expect("park");
        register_wait(&vault, &trap, 1).expect("register wait");

        let is_parked = runner.parked_attempt(attempt_id).expect("parked").is_some();
        assert!(is_parked);
        let record = queue
            .get(attempt_id)
            .expect("read attempt")
            .expect("attempt");
        let node = crate::run_tree::render_run_tree(vec![record])
            .expect("render tree")
            .roots
            .remove(0);
        let presence = ChildAgentPresence::from_run_tree_node_with_park(&node, is_parked)
            .expect("parked child");
        let waiting = render_agents_section(&[presence], &[]);
        assert!(
            waiting.rows[0]
                .line
                .ends_with(AgentRunStatus::NeedsInput.as_str())
        );

        send_trap_signal(&vault, &trap.trap_claim_id, step_hash, 2).expect("send signal");
        consume_trap_signal(&vault, &runner, &trap, 3).expect("consume signal");
        let is_parked = runner.parked_attempt(attempt_id).expect("parked").is_some();
        assert!(!is_parked);
        let record = queue
            .get(attempt_id)
            .expect("read resumed")
            .expect("resumed");
        let node = crate::run_tree::render_run_tree(vec![record])
            .expect("render resumed tree")
            .roots
            .remove(0);
        let presence = ChildAgentPresence::from_run_tree_node_with_park(&node, is_parked)
            .expect("working child");
        let resumed = render_agents_section(&[presence], &[]);
        assert!(
            resumed.rows[0]
                .line
                .ends_with(AgentRunStatus::Working.as_str())
        );
    }

    fn child(id: &str) -> ChildAgentPresence {
        ChildAgentPresence {
            id: id.to_owned(),
            status: AgentRunStatus::Working,
            label: None,
            role: AGENT_ROLE_WORKER.to_owned(),
        }
    }

    fn peer(actor_handle: &str) -> PeerPresence {
        PeerPresence {
            actor_handle: actor_handle.to_owned(),
            harness_label: "claude-code".to_owned(),
            last_seen: Some(1),
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
        assert_eq!(child_a.line, "child_a working");
        let child_b = child_rows
            .iter()
            .find(|row| row.id == "child_b")
            .expect("child_b row must be rendered");
        assert_eq!(child_b.line, "child_b working");

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
        assert_eq!(section.rows[0].line, "child_a spoof working");
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
            Some(AgentRunStatus::Working)
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
        let present_children: Vec<(&str, Option<&str>, AgentRunStatus)> = lifecycle_presences
            .iter()
            .filter_map(|presence| presence.as_ref())
            .map(|child| (child.id.as_str(), child.label.as_deref(), child.status))
            .collect();
        assert_eq!(
            present_children,
            [
                ("attempt_q", Some("child_q"), AgentRunStatus::Spawned),
                ("attempt_a", Some("child_a"), AgentRunStatus::Working),
                ("attempt_p", Some("child_p"), AgentRunStatus::NeedsInput),
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
                "attempt_1 researcher working",
                "attempt_2 researcher working"
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
    /// A lead is read off the EXISTING run tree — a node with agent-dispatch
    /// children — never off a second store or a caller-supplied flag.
    #[test]
    fn lead_and_worker_labels_come_from_existing_run_tree_children() {
        let worker_a = run_tree_node("attempt_w1", Some("worker"), RunTreeStatus::Running);
        let worker_b = run_tree_node("attempt_w2", Some("worker"), RunTreeStatus::Running);
        let helper = run_tree_node("attempt_h1", Some("helper"), RunTreeStatus::Running);
        let mut leading_worker = worker_a.clone();
        leading_worker.children = vec![helper];
        let mut lead = run_tree_node(
            "attempt_lead",
            Some("sys.team_lead"),
            RunTreeStatus::Running,
        );
        lead.children = vec![leading_worker, worker_b.clone()];

        assert_eq!(agent_role_token(&lead), AGENT_ROLE_LEAD);
        assert_eq!(agent_role_token(&worker_a), AGENT_ROLE_WORKER);
        assert_eq!(agent_role_token(&lead.children[0]), AGENT_ROLE_LEAD);
        assert_eq!(agent_role_token(&lead.children[1]), AGENT_ROLE_WORKER);

        // A non-agent child never promotes its parent to a lead.
        let mut with_maintenance = worker_b;
        with_maintenance.children = vec![run_tree_node_with_worker_kind(
            "attempt_maint",
            None,
            RunTreeStatus::Running,
            "dreamer",
        )];
        assert_eq!(agent_role_token(&with_maintenance), AGENT_ROLE_WORKER);
    }

    /// Whole-tree observation walks the ONE existing `RunTree`: lead → workers
    /// → depth-2 helper, in tree order, with per-spawn identity intact.
    #[test]
    fn branch_presence_walks_one_existing_tree_and_labels_each_level() {
        let mut worker_a = run_tree_node("attempt_w1", Some("worker"), RunTreeStatus::Running);
        worker_a.children = vec![run_tree_node(
            "attempt_h1",
            Some("helper"),
            RunTreeStatus::Running,
        )];
        let mut lead = run_tree_node(
            "attempt_lead",
            Some("sys.team_lead"),
            RunTreeStatus::Running,
        );
        lead.children = vec![
            worker_a,
            run_tree_node("attempt_w2", Some("worker"), RunTreeStatus::Running),
        ];

        let presences = ChildAgentPresence::from_run_tree_branch(&lead);

        let observed: Vec<(&str, &str)> = presences
            .iter()
            .map(|child| (child.id.as_str(), child.role.as_str()))
            .collect();
        assert_eq!(
            observed,
            [
                ("attempt_lead", AGENT_ROLE_LEAD),
                ("attempt_w1", AGENT_ROLE_LEAD),
                ("attempt_h1", AGENT_ROLE_WORKER),
                ("attempt_w2", AGENT_ROLE_WORKER),
            ]
        );

        let section = render_agents_section(&presences, &[]);
        let lines: Vec<&str> = section.rows.iter().map(|row| row.line.as_str()).collect();
        assert_eq!(
            lines,
            [
                "attempt_lead sys.team_lead working lead",
                "attempt_w1 worker working lead",
                "attempt_h1 helper working",
                "attempt_w2 worker working",
            ]
        );
    }

    /// A terminal node leaves the section even when it led a subtree, and its
    /// live descendants keep rendering: presence is "working here now".
    #[test]
    fn terminal_lead_leaves_the_section_without_hiding_live_descendants() {
        let mut lead = run_tree_node(
            "attempt_lead",
            Some("sys.team_lead"),
            RunTreeStatus::Completed,
        );
        lead.children = vec![run_tree_node(
            "attempt_w1",
            Some("worker"),
            RunTreeStatus::Running,
        )];

        let presences = ChildAgentPresence::from_run_tree_branch(&lead);

        assert_eq!(presences.len(), 1);
        assert_eq!(presences[0].id, "attempt_w1");
        assert_eq!(presences[0].role, AGENT_ROLE_WORKER);
    }
}
