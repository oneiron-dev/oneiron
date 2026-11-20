//! The attribution index: who made each visible thing of the live deck,
//! rebuilt from the stamped operation log.

use super::{ChangeKind, DeckOp, LiveDeck, NodeId, StampedOp};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// The rebuildable attribution index: who made each visible thing, without
/// replaying history per inspection. Imported content resolves to no actor.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttributionIndex {
    /// Node -> (actor, at) of its creation operation.
    pub created_by: BTreeMap<NodeId, (String, u64)>,
    /// Node -> contributing (actor, kind, at), causally last per actor/kind.
    pub contributions: BTreeMap<NodeId, Vec<(String, ChangeKind, u64)>>,
    /// Container -> actors with edits anywhere below it (cached summaries).
    pub descendant_actors: BTreeMap<NodeId, Vec<String>>,
}

impl AttributionIndex {
    /// Rebuild from the current deck and its stamped operation log. The log
    /// is the input; the index is a checkpoint that compaction may carry so
    /// authorship of visible content survives it.
    pub fn build(deck: &LiveDeck, log: &[StampedOp]) -> Self {
        let mut index = Self::default();
        // Minting is sequential, so the identities creation operations
        // produced are recoverable: the log's mints (its unnamed creations,
        // then the series their charts carried unnamed, and the rows,
        // columns and series its table and chart edits inserted unnamed) are
        // the last mints below the deck's high-water mark, in log order.
        let creates: u64 = log.iter().map(|stamped| stamped.op.unnamed()).sum();
        let mut next_mint = deck.next_node.saturating_sub(creates);
        for stamped in log {
            let kind = stamped.op.kind();
            let created = match stamped.op {
                DeckOp::AddSlide { id: Some(id) } | DeckOp::AddNode { id: Some(id), .. } => {
                    Some(id)
                }
                DeckOp::AddSlide { id: None } | DeckOp::AddNode { id: None, .. } => {
                    Some(NodeId(next_mint))
                }
                _ => None,
            };
            next_mint += stamped.op.unnamed();
            let effective = created.or_else(|| stamped.op.target());
            if let Some(target) = effective {
                if kind == ChangeKind::Creation {
                    index
                        .created_by
                        .entry(target)
                        .or_insert_with(|| (stamped.made_by.clone(), stamped.at));
                }
                let entries = index.contributions.entry(target).or_default();
                entries.retain(|(actor, existing, _)| {
                    !(actor == &stamped.made_by && *existing == kind)
                });
                entries.push((stamped.made_by.clone(), kind, stamped.at));
            }
            // Summary actors on every ancestor of the touched node.
            if let Some(mut node) = effective
                && let Some(first) = deck.nodes.get(&node)
            {
                let mut cursor = first.parent;
                while let Some(parent) = cursor {
                    node = parent;
                    let actors = index.descendant_actors.entry(node).or_default();
                    if !actors.contains(&stamped.made_by) {
                        actors.push(stamped.made_by.clone());
                    }
                    cursor = deck.nodes.get(&node).and_then(|found| found.parent);
                }
            }
        }
        index
    }

    /// The actor that created `node`; `None` for imported content.
    pub fn creator(&self, node: NodeId) -> Option<&str> {
        self.created_by.get(&node).map(|(actor, _)| actor.as_str())
    }
}
