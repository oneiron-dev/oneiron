//! Evidence of forks in a project's signed history (decision 10), mirroring
//! the handoff equivocation records: every node of the authenticated held DAG
//! with two or more valid children, on the served path or under a suppressed
//! branch, with the outcome rank and settlement gave there. It is evidence for
//! the owner, never a reason to admit. Records live with the vault handle and
//! go when it closes; a fold over a committed snapshot publishes them.
use super::fold::ProjectRank;
use super::revision::ProjectRevisionHash;
use crate::{EntityId, Vault};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Mutex, PoisonError};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ProjectForkEvidence {
    pub project: EntityId,
    pub anchor: ProjectRevisionHash,
    /// Every valid child of `anchor`.
    pub children: BTreeSet<ProjectRevisionHash>,
    pub outcome: ProjectForkOutcome,
    /// Whether `anchor` lies on the served path; false under a suppressed branch.
    pub on_path: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum ProjectForkOutcome {
    Ranked {
        winner: ProjectRevisionHash,
    },
    Resolved {
        resolution: ProjectRevisionHash,
        winner: ProjectRevisionHash,
    },
    Tied {
        rank: ProjectRank,
    },
}

impl ProjectForkEvidence {
    /// Machine-readable record discriminator; presentation text belongs to hosts.
    pub const KIND: &'static str = "project_fork";
}

/// The most records one vault handle keeps, as for handoff equivocations.
const RECORD_LIMIT: usize = 256;

#[derive(Default)]
struct Records {
    /// One record per fork, `(project, anchor)`: the latest view of it, so
    /// a fork that grows one sibling at a time spends one slot (Wonder r6 F7).
    held: BTreeMap<(EntityId, ProjectRevisionHash), ProjectForkEvidence>,
    /// New records refused past [`RECORD_LIMIT`].
    dropped: u64,
}

/// This vault handle's records, first come.
#[derive(Default)]
pub(crate) struct ProjectForks(Mutex<Records>);

impl ProjectForks {
    /// Keeps the latest view of each fork and logs each change once. Past
    /// the bound, a new fork is dropped; only the first dropped record and
    /// each power of two log, with the count. It decides under the lock and
    /// logs after it.
    pub(crate) fn record(&self, evidence: ProjectForkEvidence) -> bool {
        let dropped = {
            let mut records = self.records();
            let key = (evidence.project, evidence.anchor);
            if records.held.get(&key) == Some(&evidence) {
                return false;
            }
            if records.held.contains_key(&key) || records.held.len() < RECORD_LIMIT {
                records.held.insert(key, evidence.clone());
                None
            } else {
                records.dropped += 1;
                if !records.dropped.is_power_of_two() {
                    return false;
                }
                Some(records.dropped)
            }
        };
        match dropped {
            None => tracing::warn!(
                kind = ProjectForkEvidence::KIND,
                project = %evidence.project.to_hex(),
                anchor = ?evidence.anchor,
                children = evidence.children.len(),
                outcome = ?evidence.outcome,
                on_path = evidence.on_path,
                "project history forked"
            ),
            Some(dropped) => tracing::warn!(
                kind = ProjectForkEvidence::KIND,
                dropped,
                "project fork records past the bound were dropped"
            ),
        }
        true
    }

    fn records(&self) -> std::sync::MutexGuard<'_, Records> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl Vault {
    /// The latest view of each fork that folds over committed snapshots found
    /// since this handle opened.
    #[must_use]
    pub fn project_forks(&self) -> Vec<ProjectForkEvidence> {
        self.store
            .project_forks
            .records()
            .held
            .values()
            .cloned()
            .collect()
    }

    /// How many fork records this handle dropped past its bound.
    #[must_use]
    pub fn project_forks_dropped(&self) -> u64 {
        self.store.project_forks.records().dropped
    }
}
