//! Vault-backed run-tree read adapter, failure-marker overlay, and label helper.

use crate::Vault;
use crate::attempt_queue::{AttemptId, AttemptQueue};
use crate::entity_id::bytes_to_hex_lower;
use crate::error::{Error, Result};

use super::consent::gate_consent_bundle_name;
use super::render::render_run_tree_presorted;
use super::types::{
    RunTree, RunTreeFailureDiagram, RunTreeNode, RunTreeNodeMarker, RunTreeNodeMarkerKind,
    RunTreeStatus,
};
use crate::error::ArtifactError;

/// Read adapter over the runtime attempt queue.
pub struct RunTreeAdapter<'a> {
    queue: AttemptQueue<'a>,
    vault: &'a Vault,
}

impl<'a> RunTreeAdapter<'a> {
    /// Opens a run-tree read adapter over an already-open vault.
    #[must_use]
    pub fn new(vault: &'a Vault) -> Self {
        Self {
            queue: AttemptQueue::new(vault),
            vault,
        }
    }

    /// Renders all persisted attempt rows into deterministic roots and children.
    pub fn read(&self) -> Result<RunTree> {
        render_run_tree_presorted(self.queue.list()?)
    }

    /// Renders persisted rows for one run id into deterministic roots and
    /// children.
    pub fn read_run(&self, run_id: &str) -> Result<RunTree> {
        let mut tree = render_run_tree_presorted(self.queue.list_run(run_id)?)?;
        let paused = self
            .vault
            .gate_breaker_run_projection(run_id)?
            .gate_breaker_paused;
        tree.set_gate_breaker_paused_marker(paused);
        Ok(tree)
    }

    /// Engine-generated display name and agent label for one run's consent
    /// bundle, as `(name, agent_label)`.
    ///
    /// The label is the first nonempty root [`RunTreeNode::agent_id`] in
    /// deterministic run-tree order; the name is `"{agent label} · {id8}"`, or
    /// [`GATE_CONSENT_BUNDLE_FALLBACK_LABEL`] followed by the same fragment
    /// when the run tree exposes no dispatched agent. `id8` is the first eight
    /// lowercase hex characters of the bundle id.
    ///
    /// Read-only: it renders durable attempt rows and writes nothing.
    ///
    /// # Errors
    ///
    /// Propagates storage failures from the attempt-queue read. A run the
    /// attempt queue cannot NAME — a run id it refuses, or an undecodable
    /// attempt row — is not one of them: naming is presentation metadata over
    /// an identity the bundle digest already fixed, so an unnameable tree
    /// takes the fallback label rather than making its bundle unreviewable.
    pub fn consent_bundle_label(
        &self,
        dreamer_run_id: &str,
        bundle_id: &[u8; 32],
    ) -> Result<(String, Option<String>)> {
        let agent_label = match self.read_run(dreamer_run_id) {
            Ok(tree) => first_root_agent_label(&tree),
            Err(Error::Artifact(ArtifactError::InvalidAttemptQueueRecord(_))) => None,
            Err(error) => return Err(error),
        };
        Ok((
            gate_consent_bundle_name(agent_label.as_deref(), bundle_id),
            agent_label,
        ))
    }
}

impl RunTree {
    /// Stamps the ONE-1453 burst-breaker pause marker on this tree.
    ///
    /// Presentation only. The caller obtains `paused` from
    /// [`crate::Vault::gate_breaker_run_projection`]; the setter never derives
    /// breaker state from attempt lifecycle status.
    ///
    /// The marker lands on exactly the deterministic FIRST root — the same
    /// root ordering ONE-1452 uses to pick a run's agent label — and every
    /// other node, root or child, stays `false`.
    pub fn set_gate_breaker_paused_marker(&mut self, paused: bool) {
        let mut nodes: Vec<_> = self.roots.iter_mut().collect();
        while let Some(node) = nodes.pop() {
            node.gate_breaker_paused = false;
            nodes.extend(node.children.iter_mut());
        }
        if let Some(root) = self.roots.first_mut() {
            root.gate_breaker_paused = paused;
        }
    }
}

/// Marks the failing node of an already-rendered tree.
///
/// A PURE overlay: it walks `roots`/`children`, requires EXACTLY ONE matching
/// node, and mutates nothing — every status, event, timestamp, and failure
/// field is carried through untouched.
///
/// # Errors
///
/// [`Error::InvalidConfig`] when the tree does not contain exactly one node
/// under `failing_attempt_id`.
pub fn mark_run_tree_failure(
    tree: RunTree,
    failing_attempt_id: AttemptId,
) -> Result<RunTreeFailureDiagram> {
    let attempt_id = bytes_to_hex_lower(failing_attempt_id.as_bytes());
    let (matched, failed) = count_marked_nodes(&tree.roots, &attempt_id);
    if matched != 1 || !failed {
        return Err(Error::InvalidConfig(format!(
            "a run-tree failure marker must name exactly one rendered Failed node, found {matched}"
        )));
    }
    Ok(RunTreeFailureDiagram {
        tree,
        marker: RunTreeNodeMarker {
            attempt_id,
            kind: RunTreeNodeMarkerKind::Failing,
        },
    })
}

fn count_marked_nodes(nodes: &[RunTreeNode], attempt_id: &str) -> (usize, bool) {
    nodes.iter().fold((0, false), |(count, failed), node| {
        let (children, failed_child) = count_marked_nodes(&node.children, attempt_id);
        let matches = node.attempt_id == attempt_id;
        (
            count + usize::from(matches) + children,
            failed || failed_child || (matches && node.status == RunTreeStatus::Failed),
        )
    })
}

/// The first nonempty root agent label in deterministic run-tree order.
fn first_root_agent_label(tree: &RunTree) -> Option<String> {
    tree.roots.iter().find_map(|root| {
        root.agent_id
            .as_deref()
            .map(str::trim)
            .filter(|label| !label.is_empty())
            .map(str::to_owned)
    })
}
