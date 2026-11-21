//! Moved from `crates/oneiron/src/workspace_roster/project/fold.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use oneiron_model::llm::Scope;
use oneiron_verb_wire::workspace_roster::project::revision::ProjectRevisionHash;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeSet;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProjectRank {
    /// The parent's leader, not on the parent's board.
    Leader,
    /// A board holder at the parent, or the host acting for the owner.
    Board,
}

/// Per axis: unconstrained meets constrained, equal values stay, two
/// different values meet to nothing; resource sets intersect.
pub fn slice_meet(a: &Scope, b: &Scope) -> Option<Scope> {
    fn axis(a: Option<EntityId>, b: Option<EntityId>) -> Option<Option<EntityId>> {
        match (a, b) {
            (Some(a), Some(b)) if a != b => None,
            (a, b) => Some(a.or(b)),
        }
    }
    Some(Scope {
        world: axis(a.world, b.world)?,
        facet: axis(a.facet, b.facet)?,
        // A relationship set meets as one value: equal sets stay, two
        // different sets meet to nothing.
        relationship: match (&a.relationship, &b.relationship) {
            (Some(left), Some(right)) if left != right => return None,
            (left, right) => left.clone().or_else(|| right.clone()),
        },
        project: axis(a.project, b.project)?,
        readable: a.readable.intersection(&b.readable).cloned().collect(),
        writable: a.writable.intersection(&b.writable).cloned().collect(),
    })
}

/// One fork a parent cycle leaves open (ruling (a)): its worlds tie there,
/// or install different children there.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectForkConflict {
    pub anchor: ProjectRevisionHash,
    pub rank: ProjectRank,
    /// Every child of `anchor` some world keeps in contention or installs.
    pub contenders: BTreeSet<ProjectRevisionHash>,
    /// The causal resolution tips at `anchor` (ruling (b)).
    pub resolution_tips: BTreeSet<ProjectRevisionHash>,
}
